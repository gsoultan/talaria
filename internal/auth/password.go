// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package auth hashes passwords, issues session tokens and limits login
// attempts.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: 19 MiB, 2 passes, 1 lane (the OWASP minimum). Each
// login costs about 19 MiB for a few tens of milliseconds, which the
// concurrency limit in Hasher keeps bounded on a 2 GB box.
const (
	memory  = 19 * 1024
	passes  = 2
	threads = 1
	keyLen  = 32
	saltLen = 16
)

var b64 = base64.RawStdEncoding

// sem bounds concurrent hashes so a login burst cannot exhaust memory.
var sem = make(chan struct{}, 4)

// HashPassword returns a PHC-format Argon2id hash.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	if len(password) > 1024 {
		return "", errors.New("password is too long")
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)
	sem <- struct{}{}
	key := argon2.IDKey([]byte(password), salt, passes, memory, threads, keyLen)
	<-sem
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, passes, threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// dummy is verified against when the user does not exist, so timing does not
// reveal which addresses are valid.
var dummy, _ = HashPassword("not-a-real-password")

// CheckPassword reports whether password matches hash. An empty hash checks
// against a dummy and always fails.
func CheckPassword(hash, password string) bool {
	ok := true
	if hash == "" {
		hash, ok = dummy, false
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || len(password) > 1024 {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m > 256*1024 || t > 10 || p == 0 {
		return false
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	sem <- struct{}{}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	<-sem
	return subtle.ConstantTimeCompare(got, want) == 1 && ok
}

// NewToken returns a random 256-bit URL-safe token.
func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

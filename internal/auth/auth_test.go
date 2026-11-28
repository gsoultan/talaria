// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong horse") || CheckPassword("", "correct horse") {
		t.Fatal("check")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if CheckPassword("$argon2id$v=19$m=99999999,t=1,p=1$AA$AA", "x") {
		t.Fatal("hostile params")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	l.Fail("ip")
	l.Fail("ip")
	if l.Allowed("ip") || !l.Allowed("other") {
		t.Fatal("limit")
	}
	now = now.Add(2 * time.Minute)
	if !l.Allowed("ip") {
		t.Fatal("window")
	}
}

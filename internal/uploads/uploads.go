// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package uploads keeps files attached to messages being written, on disk,
// until the message is sent or the upload expires. Each upload belongs to one
// user; nobody else can read it.
package uploads

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
)

// Limits per user, so one account cannot fill the disk.
const (
	maxFilesPerUser = 50
	defaultTTL      = 24 * time.Hour
)

// ErrTooLarge means the file, or the user's uploads together, are over the
// limit.
var ErrTooLarge = errors.New("uploads: too large")

type item struct {
	domain.Upload
	user    int64
	path    string
	expires time.Time
}

// Store holds uploads in a directory.
type Store struct {
	dir     string
	maxSize int64 // per file; the user's total may be four times this
	ttl     time.Duration

	mu    sync.Mutex
	items map[string]*item
}

// New returns a store in dir, removing files left from an earlier run.
func New(dir string, maxSize int64) (*Store, error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, maxSize: maxSize, ttl: defaultTTL, items: map[string]*item{}}, nil
}

// MaxSize is the largest file the store takes.
func (s *Store) MaxSize() int64 { return s.maxSize }

// Put stores r for userID, reading at most MaxSize bytes.
func (s *Store) Put(userID int64, filename, contentType string, r io.Reader) (domain.Upload, error) {
	s.sweep()
	s.mu.Lock()
	var files int
	var total int64
	for _, it := range s.items {
		if it.user == userID {
			files++
			total += it.Size
		}
	}
	s.mu.Unlock()
	if files >= maxFilesPerUser || total >= 4*s.maxSize {
		return domain.Upload{}, fmt.Errorf("%w: remove some attachments or send the message first", ErrTooLarge)
	}
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	path := filepath.Join(s.dir, id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return domain.Upload{}, err
	}
	n, err := io.Copy(f, io.LimitReader(r, s.maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > s.maxSize {
		err = ErrTooLarge
	}
	if err != nil {
		os.Remove(path)
		return domain.Upload{}, err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if filename == "" {
		filename = "attachment"
	}
	up := domain.Upload{ID: id, Filename: filename, ContentType: contentType, Size: n}
	s.mu.Lock()
	s.items[id] = &item{Upload: up, user: userID, path: path, expires: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return up, nil
}

// Read returns an upload of userID with its content.
func (s *Store) Read(_ context.Context, userID int64, id string) (domain.Upload, []byte, error) {
	s.mu.Lock()
	it, ok := s.items[id]
	if ok && (it.user != userID || time.Now().After(it.expires)) {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return domain.Upload{}, nil, kakarot.NotFound("upload", id)
	}
	data, err := os.ReadFile(it.path)
	if err != nil {
		return domain.Upload{}, nil, kakarot.NotFound("upload", id)
	}
	return it.Upload, data, nil
}

// sweep removes expired uploads.
func (s *Store) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, it := range s.items {
		if now.After(it.expires) {
			os.Remove(it.path)
			delete(s.items, id)
		}
	}
}

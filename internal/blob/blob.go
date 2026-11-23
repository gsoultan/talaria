// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package blob stores raw message bodies on disk, zstd-compressed and
// content-addressed. The address is SHA-256 over the tenant id and the raw
// bytes, so identical messages are stored once per tenant and never shared
// across tenants.
package blob

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Store is a directory of compressed blobs.
type Store struct {
	dir  string
	encs sync.Pool
	// gc keeps garbage collection from deleting a file that a delivery is
	// about to reference: writers hold it shared, the collector exclusively.
	gc sync.RWMutex
}

// Hold blocks garbage collection until the returned func is called. Hold it
// from Put until the database row referencing the blob is committed.
func (s *Store) Hold() func() {
	s.gc.RLock()
	return s.gc.RUnlock
}

// Collect runs deleteRow under the collector lock and removes the file when
// it reports that the row is gone.
func (s *Store) Collect(tenantID int64, hash []byte, deleteRow func() (bool, error)) error {
	s.gc.Lock()
	defer s.gc.Unlock()
	ok, err := deleteRow()
	if err != nil || !ok {
		return err
	}
	return s.Delete(tenantID, hash)
}

// Open creates the blob directory if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) encoder(w io.Writer) *zstd.Encoder {
	if e, ok := s.encs.Get().(*zstd.Encoder); ok {
		e.Reset(w)
		return e
	}
	// One goroutine and a 1 MiB window keep each encoder to a few MiB.
	e, _ := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20),
		zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithLowerEncoderMem(true))
	return e
}

func (s *Store) path(tenantID int64, hash []byte) string {
	h := hex.EncodeToString(hash)
	return filepath.Join(s.dir, strconv.FormatInt(tenantID, 10), h[:2], h[2:]+".zst")
}

// Result describes a stored blob.
type Result struct {
	Hash       []byte
	Size       int64
	StoredSize int64
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// ErrTooLarge is returned when a body exceeds the size limit.
var ErrTooLarge = errors.New("message too large")

// Put streams r to disk. Memory use is bounded by the encoder window, not by
// the message size. limit <= 0 means no limit.
func (s *Store) Put(tenantID int64, r io.Reader, limit int64) (Result, error) {
	tmp, err := os.CreateTemp(filepath.Join(s.dir, "tmp"), "put-*")
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := sha256.New()
	var tid [8]byte
	binary.BigEndian.PutUint64(tid[:], uint64(tenantID))
	h.Write(tid[:])

	cw := &countWriter{w: tmp}
	enc := s.encoder(cw)
	src := r
	if limit > 0 {
		src = io.LimitReader(r, limit+1)
	}
	n, err := io.Copy(io.MultiWriter(enc, h), src)
	if err == nil {
		err = enc.Close()
	}
	s.encs.Put(enc)
	if err != nil {
		return Result{}, err
	}
	if limit > 0 && n > limit {
		return Result{}, ErrTooLarge
	}
	res := Result{Hash: h.Sum(nil), Size: n, StoredSize: cw.n}
	dst := s.path(tenantID, res.Hash)
	if _, err := os.Stat(dst); err == nil {
		return res, nil // already stored
	}
	if err := tmp.Sync(); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return Result{}, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return Result{}, err
	}
	return res, nil
}

type reader struct {
	*zstd.Decoder
	f *os.File
}

func (r reader) Close() error {
	r.Decoder.Close()
	return r.f.Close()
}

// Open returns the decompressed body.
func (s *Store) Open(tenantID int64, hash []byte) (io.ReadCloser, error) {
	f, err := os.Open(s.path(tenantID, hash))
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	d, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(8<<20))
	if err != nil {
		f.Close()
		return nil, err
	}
	return reader{d, f}, nil
}

// Delete removes a blob file. A missing file is not an error.
func (s *Store) Delete(tenantID int64, hash []byte) error {
	err := os.Remove(s.path(tenantID, hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

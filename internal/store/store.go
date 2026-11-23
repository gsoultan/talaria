// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package store keeps Talaria's metadata in SQLite: tenants, domains, users,
// sessions, mailboxes and message summaries. Message bodies live in the blob
// store; this package only holds references to them.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo
)

//go:embed migrations/*.sql
var migrations embed.FS

// Errors returned by the store.
var (
	ErrNotFound      = errors.New("not found")
	ErrExists        = errors.New("already exists")
	ErrQuotaExceeded = errors.New("quota exceeded")
	ErrSeatLimit     = errors.New("tenant seat limit reached")
	ErrInvalid       = errors.New("invalid")
)

// Store wraps two connection pools: a single writer (SQLite allows one writer
// at a time, so queuing in Go is cheaper than lock retries) and a small pool
// of readers that run concurrently under WAL.
type Store struct {
	w   *sql.DB
	r   *sql.DB
	now func() time.Time
}

// Open opens or creates the database in dir and applies migrations.
func Open(dir string) (*Store, error) {
	path := filepath.Join(dir, "talaria.db")
	// Small page cache and mmap window keep RSS predictable on a 2 GB box.
	pragmas := "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(5000)&_pragma=cache_size(-8000)&_pragma=mmap_size(67108864)&_pragma=temp_store(MEMORY)"
	w, err := sql.Open("sqlite", "file:"+path+"?"+pragmas+"&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", "file:"+path+"?"+pragmas+"&mode=ro")
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(4)
	r.SetMaxIdleConns(4)
	s := &Store{w: w, r: r, now: time.Now}
	if err := s.migrate(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes both pools.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		n, err := strconv.Atoi(strings.SplitN(filepath.Base(f), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad name", f)
		}
		if n <= version {
			continue
		}
		body, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", n))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// tx runs fn in a write transaction.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) unix() int64 { return s.now().Unix() }

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

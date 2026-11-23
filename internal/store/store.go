// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package store keeps Talaria's metadata in PostgreSQL: tenants, domains,
// users, sessions, mailboxes, message summaries and the search index.
// Message bodies live in the blob store; this package only holds references
// to them.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
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

// Options tune the connection pool.
type Options struct {
	// MaxConns caps open connections. Each PostgreSQL connection is a
	// process of its own, so a small pool keeps memory low. Default 10.
	MaxConns int
}

// Store is a pool of connections to one PostgreSQL database. w and r are
// the same pool; reads and writes are kept apart in the code so a read
// replica can be added later.
type Store struct {
	w   *db
	r   *db
	now func() time.Time
}

// Open connects to the database at url (postgres://user:pass@host/db) and
// applies migrations.
func Open(ctx context.Context, url string, o Options) (*Store, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database url: %w", err)
	}
	if cfg.RuntimeParams["application_name"] == "" {
		cfg.RuntimeParams["application_name"] = "talaria"
	}
	if o.MaxConns <= 0 {
		o.MaxConns = 10
	}
	sdb := stdlib.OpenDB(*cfg)
	sdb.SetMaxOpenConns(o.MaxConns)
	sdb.SetMaxIdleConns(min(o.MaxConns, 4))
	sdb.SetConnMaxIdleTime(5 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sdb.PingContext(pingCtx); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	d := &db{sdb}
	s := &Store{w: d, r: d, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the pool.
func (s *Store) Close() error {
	return s.w.Close()
}

// Ping checks that the database answers.
func (s *Store) Ping(ctx context.Context) error {
	return s.r.PingContext(ctx)
}

// migrationLock serializes migrations when several processes start at once.
const migrationLock = 0x74616c61 // "tala"

func (s *Store) migrate(ctx context.Context) error {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(?)`, migrationLock); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
			return err
		}
		for _, f := range files {
			n, err := strconv.Atoi(strings.SplitN(path.Base(f), "_", 2)[0])
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
			// Run as is: migrations are plain SQL, not rebound.
			if _, err := tx.Tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version(version) VALUES (?)`, n); err != nil {
				return err
			}
		}
		return nil
	})
}

// tx runs fn in a transaction.
func (s *Store) tx(ctx context.Context, fn func(*Tx) error) error {
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
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// The queries in this package use ? for parameters, which reads well next
// to dynamic IN lists; db and Tx turn them into PostgreSQL's $1, $2, ...

type db struct{ *sql.DB }

func (d *db) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, rebind(q), args...)
}

func (d *db) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, rebind(q), args...)
}

func (d *db) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, rebind(q), args...)
}

func (d *db) BeginTx(ctx context.Context, o *sql.TxOptions) (*Tx, error) {
	tx, err := d.DB.BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &Tx{tx}, nil
}

// Tx is a transaction taking ? parameters.
type Tx struct{ *sql.Tx }

func (t *Tx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, rebind(q), args...)
}

func (t *Tx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, rebind(q), args...)
}

func (t *Tx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, rebind(q), args...)
}

var rebound sync.Map // query → rebound query; queries come from a small fixed set

// rebind replaces each ? outside quotes with $1, $2, ...
func rebind(q string) string {
	if v, ok := rebound.Load(q); ok {
		return v.(string)
	}
	var b strings.Builder
	b.Grow(len(q) + 16)
	n, quoted := 0, false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '\'':
			quoted = !quoted
		case c == '?' && !quoted:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()
	if len(q) < 4096 {
		rebound.Store(q, out)
	}
	return out
}

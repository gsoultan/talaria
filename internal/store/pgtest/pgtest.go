// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package pgtest gives each test an empty PostgreSQL schema of its own.
//
// Tests run against the database in TALARIA_TEST_DATABASE_URL, for example
// postgres://talaria:talaria@localhost:5432/talaria_test. Without it, tests
// that need a database are skipped.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Env names the variable holding the test database URL.
const Env = "TALARIA_TEST_DATABASE_URL"

// URL creates a fresh schema, drops it when the test ends, and returns a
// database URL whose search_path is that schema.
func URL(t testing.TB) string {
	t.Helper()
	base := os.Getenv(Env)
	if base == "" {
		t.Skip(Env + " is not set; skipping a test that needs PostgreSQL")
	}
	b := make([]byte, 6)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	db, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		db.Close()
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		db.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

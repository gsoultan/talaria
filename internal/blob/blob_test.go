// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package blob

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPutOpen(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("Subject: hi\r\n\r\nhello world\r\n", 1000)
	a, err := s.Put(1, strings.NewReader(body), 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.Size != int64(len(body)) || a.StoredSize >= a.Size/10 {
		t.Fatalf("sizes %+v", a)
	}
	b, _ := s.Put(1, strings.NewReader(body), 0)
	c, _ := s.Put(2, strings.NewReader(body), 0)
	if !bytes.Equal(a.Hash, b.Hash) || bytes.Equal(a.Hash, c.Hash) {
		t.Fatal("dedupe must be per tenant")
	}
	r, err := s.Open(1, a.Hash)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != body {
		t.Fatal("round trip")
	}
	if _, err := s.Put(1, strings.NewReader(body), 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	if err := s.Delete(1, a.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(1, a.Hash); err == nil {
		t.Fatal("deleted")
	}
}

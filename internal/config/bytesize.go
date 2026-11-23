// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ByteSize is a size in bytes that parses from strings like "512MiB" or "25MB".
type ByteSize int64

const (
	KiB ByteSize = 1 << (10 * (iota + 1))
	MiB
	GiB
)

var units = []struct {
	suffix string
	mult   ByteSize
}{
	{"KIB", KiB}, {"MIB", MiB}, {"GIB", GiB},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	{"B", 1},
}

// ParseByteSize parses a human-readable size.
func ParseByteSize(s string) (ByteSize, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := ByteSize(1)
	for _, u := range units {
		if strings.HasSuffix(t, u.suffix) {
			mult, t = u.mult, strings.TrimSpace(strings.TrimSuffix(t, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return ByteSize(n) * mult, nil
}

func (b *ByteSize) UnmarshalText(text []byte) error {
	v, err := ParseByteSize(string(text))
	if err != nil {
		return err
	}
	*b = v
	return nil
}

func (b ByteSize) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(b), 10) + "B"), nil
}

// Duration is a time.Duration that parses from strings like "30s" or "5m".
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q", text)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

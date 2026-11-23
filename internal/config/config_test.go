// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	cases := map[string]ByteSize{"512MiB": 512 * MiB, "25MB": 25_000_000, "1GiB": GiB, "100": 100, " 4 KiB ": 4 * KiB}
	for in, want := range cases {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "MiB", "-1", "12XB"} {
		if _, err := ParseByteSize(bad); err == nil {
			t.Errorf("ParseByteSize(%q) succeeded, want error", bad)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "talaria.toml")
	body := `hostname = "mail.example.com"
memory_limit = "256MiB"
[outbound]
mode = "relay"
[outbound.relay]
host = "smtp.relay.example"
port = 465
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "mail.example.com" || cfg.MemoryLimit != 256*MiB || cfg.Outbound.Relay.Port != 465 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.SMTP.MaxMessageSize != 25*MiB {
		t.Fatalf("defaults not kept: %+v", cfg.SMTP)
	}
}

func TestLoadRejectsUnknownKeysAndBadMode(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown": "hostnme = \"typo\"\n",
		"mode":    "[outbound]\nmode = \"carrier-pigeon\"\n",
	} {
		p := filepath.Join(dir, name+".toml")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load succeeded, want error", name)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := Load("../../talaria.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Outbound.Relay.Timeout.D().Seconds() != 30 {
		t.Fatalf("relay timeout = %v", cfg.Outbound.Relay.Timeout)
	}
}

// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Command talaria runs the Talaria mail server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/gsoultan/talaria/internal/api"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/server"
)

func main() {
	configPath := flag.String("config", os.Getenv("TALARIA_CONFIG"), "path to talaria.toml")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("talaria %s (%s)\n", api.Version, api.Commit)
		return
	}
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "talaria:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)

	// A GOMEMLIMIT env var set by the operator wins over the config file.
	if os.Getenv("GOMEMLIMIT") == "" && cfg.MemoryLimit > 0 {
		debug.SetMemoryLimit(int64(cfg.MemoryLimit))
	}
	log.Info("starting talaria", "version", api.Version, "hostname", cfg.Hostname,
		"memory_limit", debug.SetMemoryLimit(-1), "outbound", cfg.Outbound.Mode, "tls", cfg.TLS.Mode)

	srv, err := server.New(cfg, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func newLogger(c config.Log) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(c.Level)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

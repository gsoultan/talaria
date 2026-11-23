// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/server"
	"github.com/gsoultan/talaria/internal/store"
)

const adminUsage = `Usage:
  talaria [-config FILE]                         run the server
  talaria init     -tenant NAME -domain DOMAIN -admin EMAIL
                                                 create the first tenant, domain and platform admin
  talaria tenant   -name NAME [-display NAME] [-seats N]
  talaria domain   -tenant NAME -domain DOMAIN
  talaria user     -tenant NAME -email EMAIL [-name NAME] [-role user|admin|platform]
  talaria alias    -tenant NAME -alias EMAIL -to EMAIL
  talaria passwd   -email EMAIL

Passwords are read from the terminal, or from stdin when it is not a terminal.
Every command also takes -config FILE (or TALARIA_CONFIG).
`

// runAdmin handles the management subcommands. It reports whether args named
// one.
func runAdmin(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("TALARIA_CONFIG"), "path to talaria.toml")
	tenant := fs.String("tenant", "", "tenant name")
	name := fs.String("name", "", "name")
	display := fs.String("display", "", "display name")
	domain := fs.String("domain", "", "domain")
	email := fs.String("email", "", "email address")
	admin := fs.String("admin", "", "admin email address")
	role := fs.String("role", "user", "user, admin or platform")
	alias := fs.String("alias", "", "alias address")
	to := fs.String("to", "", "user the alias delivers to")
	seats := fs.Int64("seats", 0, "seat limit (0 = unlimited)")
	switch cmd {
	case "init", "tenant", "domain", "user", "alias", "passwd":
	case "help", "-h", "-help", "--help":
		fmt.Print(adminUsage)
		return true, nil
	default:
		return false, nil
	}
	fs.Usage = func() { fmt.Fprint(os.Stderr, adminUsage) }
	if err := fs.Parse(args[1:]); err != nil {
		return true, err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return true, err
	}
	st, _, err := server.OpenStores(cfg)
	if err != nil {
		return true, err
	}
	defer st.Close()
	ctx := context.Background()

	tenantID := func() (int64, error) {
		t, err := st.TenantByName(ctx, *tenant)
		if err != nil {
			return 0, fmt.Errorf("tenant %q: %w", *tenant, err)
		}
		return t.ID, nil
	}
	switch cmd {
	case "init":
		if *tenant == "" || *domain == "" || *admin == "" {
			return true, errors.New("init needs -tenant, -domain and -admin")
		}
		pw, err := readPassword("Password for " + *admin)
		if err != nil {
			return true, err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return true, err
		}
		t, err := st.CreateTenant(ctx, store.Tenant{Name: *tenant, DisplayName: orDefault(*display, *tenant)})
		if err != nil {
			return true, err
		}
		if _, err := st.CreateDomain(ctx, t.ID, *domain); err != nil {
			return true, err
		}
		if _, err := st.CreateUser(ctx, t.ID, *admin, "Administrator", hash, store.RolePlatformAdmin, 0); err != nil {
			return true, err
		}
		fmt.Printf("Created tenant %s, domain %s and platform admin %s.\n", t.Name, *domain, *admin)
	case "tenant":
		t, err := st.CreateTenant(ctx, store.Tenant{Name: *name, DisplayName: orDefault(*display, *name), SeatLimit: *seats})
		if err != nil {
			return true, err
		}
		fmt.Printf("Created tenant %s (id %d).\n", t.Name, t.ID)
	case "domain":
		tid, err := tenantID()
		if err != nil {
			return true, err
		}
		d, err := st.CreateDomain(ctx, tid, *domain)
		if err != nil {
			return true, err
		}
		fmt.Printf("Added domain %s.\n", d.Name)
	case "user":
		tid, err := tenantID()
		if err != nil {
			return true, err
		}
		r, err := parseRole(*role)
		if err != nil {
			return true, err
		}
		pw, err := readPassword("Password for " + *email)
		if err != nil {
			return true, err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return true, err
		}
		u, err := st.CreateUser(ctx, tid, *email, *name, hash, r, 0)
		if err != nil {
			return true, err
		}
		fmt.Printf("Created user %s.\n", u.Address())
	case "alias":
		tid, err := tenantID()
		if err != nil {
			return true, err
		}
		u, err := st.UserByAddress(ctx, *to)
		if err != nil {
			return true, fmt.Errorf("user %s: %w", *to, err)
		}
		a, err := st.CreateAlias(ctx, tid, *alias, u.ID)
		if err != nil {
			return true, err
		}
		fmt.Printf("%s now delivers to %s.\n", a.Address, u.Address())
	case "passwd":
		u, err := st.UserByAddress(ctx, *email)
		if err != nil {
			return true, fmt.Errorf("user %s: %w", *email, err)
		}
		pw, err := readPassword("New password for " + u.Address())
		if err != nil {
			return true, err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return true, err
		}
		if err := st.SetPassword(ctx, u.ID, hash); err != nil {
			return true, err
		}
		fmt.Println("Password changed; existing sessions were signed out.")
	}
	return true, nil
}

func parseRole(s string) (store.Role, error) {
	switch s {
	case "user", "":
		return store.RoleUser, nil
	case "admin":
		return store.RoleTenantAdmin, nil
	case "platform":
		return store.RolePlatformAdmin, nil
	}
	return 0, fmt.Errorf("role %q: use user, admin or platform", s)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Again: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("passwords do not match")
	}
	return string(a), nil
}

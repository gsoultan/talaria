// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

import "strings"

// User is an account as the webmail and admin screens see it.
type User struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        Role   `json:"role"`
	TenantID    int64  `json:"tenantId"`
	TenantName  string `json:"tenantName"`
	QuotaBytes  int64  `json:"quotaBytes"`
	UsedBytes   int64  `json:"usedBytes"`
	Suspended   bool   `json:"suspended"`
	CreatedAt   int64  `json:"createdAt"`
}

// Login signs in with an address and password. Remember keeps the session
// for 30 days instead of 12 hours.
type Login struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Remember  bool   `json:"remember,omitzero"`
	UserAgent string `json:"-" header:"User-Agent"`
}

// Validate checks that both fields are filled in.
func (l Login) Validate() error {
	if strings.TrimSpace(l.Email) == "" {
		return invalid("email", "enter your email address")
	}
	if l.Password == "" {
		return invalid("password", "enter your password")
	}
	return nil
}

// Session is the signed-in user. The session itself travels in a cookie.
type Session struct {
	User User `json:"user"`
}

// GetMe asks for the signed-in user.
type GetMe struct{}

// Logout ends the current session.
type Logout struct{}

// ChangePassword replaces the signed-in user's password. It signs out every
// session.
type ChangePassword struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// Validate checks the new password's length.
func (c ChangePassword) Validate() error {
	if len(c.NewPassword) < 8 {
		return invalid("newPassword", "use at least 8 characters")
	}
	return nil
}

// GetInfo asks for the server version. It needs no sign-in.
type GetInfo struct{}

// Info is the server's version.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"goVersion"`
}

// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

// HeldReason says why mail was held.
type HeldReason string

// Reasons for holding mail.
const (
	HeldSpam    HeldReason = "spam"
	HeldMalware HeldReason = "malware"
)

// HeldMessage is a message in quarantine.
type HeldMessage struct {
	ID        int64      `json:"id"`
	TenantID  int64      `json:"tenantId"`
	Recipient string     `json:"recipient"`
	Reason    HeldReason `json:"reason"`
	// Detail is what the scanner found: the dangerous files, or the spam
	// tests that matched.
	Detail    string  `json:"detail"`
	SpamScore float64 `json:"spamScore"`
	EnvFrom   string  `json:"envFrom"`
	FromName  string  `json:"fromName"`
	FromAddr  string  `json:"fromAddr"`
	Subject   string  `json:"subject"`
	Size      int64   `json:"size"`
	CreatedAt int64   `json:"createdAt"`
	// CanRelease is false for malware unless an admin is asking or the
	// server lets people release it themselves.
	CanRelease bool `json:"canRelease"`
}

// HeldMessages is a page of quarantined mail.
type HeldMessages struct {
	Messages []HeldMessage `json:"messages"`
	// KeepDays is how long held mail is kept.
	KeepDays int `json:"keepDays"`
}

// ListQuarantine asks for the signed-in user's held mail.
type ListQuarantine struct {
	Query  string `json:"-" query:"q"`
	Before int64  `json:"-" query:"before"`
}

// ReleaseQuarantined delivers one of the user's held messages to their Inbox.
type ReleaseQuarantined struct {
	ID int64 `json:"-" path:"id"`
}

// DeleteQuarantined deletes one of the user's held messages.
type DeleteQuarantined struct {
	ID int64 `json:"-" path:"id"`
}

// ListHeldMail asks for a tenant's held mail.
type ListHeldMail struct {
	TenantScope
	Query  string     `json:"-" query:"q"`
	Reason HeldReason `json:"-" query:"reason"`
	Before int64      `json:"-" query:"before"`
}

// GetHeldMail asks for one held message, for review.
type GetHeldMail struct {
	ID int64 `json:"-" path:"id"`
}

// HeldMailDetail is a held message's headers, text and attachment names.
// The HTML body is never sent: held mail may be hostile.
type HeldMailDetail struct {
	Message     HeldMessage  `json:"message"`
	Headers     []Header     `json:"headers"`
	TextBody    string       `json:"textBody"`
	Attachments []Attachment `json:"attachments"`
}

// ReleaseHeldMail delivers a held message to its recipient's Inbox.
type ReleaseHeldMail struct {
	ID int64 `json:"-" path:"id"`
}

// DeleteHeldMail deletes a held message.
type DeleteHeldMail struct {
	ID int64 `json:"-" path:"id"`
}

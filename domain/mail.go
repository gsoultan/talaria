// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

import (
	"fmt"
	"strings"
)

// Mailbox is a folder with its counts.
type Mailbox struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	SpecialUse string `json:"specialUse"` // \Inbox, \Sent, \Drafts, \Trash, \Junk, \Archive or ""
	Total      int64  `json:"total"`
	Unread     int64  `json:"unread"`
	Size       int64  `json:"size"`
	Subscribed bool   `json:"subscribed"`
}

// MessageSummary is one row of a message list.
type MessageSummary struct {
	ID             int64  `json:"id"`
	MailboxID      int64  `json:"mailboxId"`
	ThreadID       int64  `json:"threadId"`
	Date           int64  `json:"date"` // received
	SentDate       int64  `json:"sentDate"`
	Size           int64  `json:"size"`
	Subject        string `json:"subject"`
	FromName       string `json:"fromName"`
	FromAddr       string `json:"fromAddr"`
	To             string `json:"to"`
	Cc             string `json:"cc"`
	Preview        string `json:"preview"`
	Seen           bool   `json:"seen"`
	Flagged        bool   `json:"flagged"`
	Answered       bool   `json:"answered"`
	Draft          bool   `json:"draft"`
	HasAttachments bool   `json:"hasAttachments"`
	SPFPass        bool   `json:"spfPass"`
	DKIMPass       bool   `json:"dkimPass"`
	DMARCPass      bool   `json:"dmarcPass"`
	ModSeq         int64  `json:"modseq"`
}

// ListMailboxes asks for the signed-in user's folders.
type ListMailboxes struct{}

// Mailboxes is a list of folders.
type Mailboxes struct {
	Mailboxes []Mailbox `json:"mailboxes"`
}

func checkName(name string) error {
	if strings.TrimSpace(name) == "" {
		return invalid("name", "enter a folder name")
	}
	return nil
}

// CreateMailbox adds a folder.
type CreateMailbox struct {
	Name string `json:"name"`
}

// Validate checks the name.
func (c CreateMailbox) Validate() error { return checkName(c.Name) }

// MailboxCreated is the new folder.
type MailboxCreated struct {
	Mailbox Mailbox `json:"mailbox"`
}

// RenameMailbox renames a folder.
type RenameMailbox struct {
	ID   int64  `json:"-" path:"id"`
	Name string `json:"name"`
}

// Validate checks the name.
func (r RenameMailbox) Validate() error { return checkName(r.Name) }

// DeleteMailbox removes a folder and the messages in it.
type DeleteMailbox struct {
	ID int64 `json:"-" path:"id"`
}

// ListMessages pages through a folder, newest first.
type ListMessages struct {
	MailboxID   int64  `json:"-" path:"mailboxId"`
	Limit       int    `json:"-" query:"limit"` // default 50, at most 200
	Cursor      string `json:"-" query:"cursor"`
	UnreadOnly  bool   `json:"-" query:"unreadOnly"`
	FlaggedOnly bool   `json:"-" query:"flaggedOnly"`
}

// MessagePage is one page of a folder. NextCursor is empty on the last
// page.
type MessagePage struct {
	Messages      []MessageSummary `json:"messages"`
	NextCursor    string           `json:"nextCursor"`
	HighestModSeq int64            `json:"highestModseq"`
}

// Search finds messages by text and filters.
type Search struct {
	Query          string `json:"-" query:"query"`
	MailboxID      int64  `json:"-" query:"mailboxId"`
	From           string `json:"-" query:"from"`
	Unread         bool   `json:"-" query:"unread"`
	Flagged        bool   `json:"-" query:"flagged"`
	HasAttachments bool   `json:"-" query:"hasAttachments"`
	After          int64  `json:"-" query:"after"`
	Before         int64  `json:"-" query:"before"`
	Limit          int    `json:"-" query:"limit"`
}

// Messages is a list of message rows.
type Messages struct {
	Messages []MessageSummary `json:"messages"`
}

// GetMessage asks for one message with its body.
type GetMessage struct {
	ID int64 `json:"-" path:"id"`
}

// Attachment is one part of a message that can be downloaded.
type Attachment struct {
	Part        string `json:"part"` // path for the download URL, such as "2.1"
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	ContentID   string `json:"contentId"`
	Inline      bool   `json:"inline"`
	// Risky types (Office files, PDFs, archives, HTML, programs) can carry
	// macros or exploits; the webmail offers a safe preview first.
	Risky bool `json:"risky"`
}

// GetAttachmentPreview asks for a safe preview of an attachment.
type GetAttachmentPreview struct {
	ID   int64  `json:"-" path:"id"`
	Part string `json:"-" path:"part"`
}

// PreviewKind is what a preview shows.
type PreviewKind string

// Preview kinds.
const (
	PreviewText  PreviewKind = "text"  // Text
	PreviewImage PreviewKind = "image" // the redrawn image at .../image
	PreviewList  PreviewKind = "list"  // Items, an archive's files
	PreviewNone  PreviewKind = "none"  // nothing to show; Note says why
)

// AttachmentPreview is what is in an attachment, read without running
// anything in it.
type AttachmentPreview struct {
	Filename    string        `json:"filename"`
	ContentType string        `json:"contentType"`
	Kind        PreviewKind   `json:"kind"`
	Text        string        `json:"text"`
	Items       []ArchiveItem `json:"items"`
	Note        string        `json:"note"`
	Truncated   bool          `json:"truncated"`
	Size        int64         `json:"size"`
	SHA256      string        `json:"sha256"`
	// Findings are what the malware scanner reports for this file.
	Findings []string `json:"findings"`
}

// ArchiveItem is a file inside an archive.
type ArchiveItem struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Encrypted bool   `json:"encrypted"`
}

// Header is one message header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MessageDetail is a message with its body, attachments and headers.
type MessageDetail struct {
	Summary               MessageSummary `json:"summary"`
	MessageID             string         `json:"messageId"`
	InReplyTo             string         `json:"inReplyTo"`
	ReplyTo               string         `json:"replyTo"`
	TextBody              string         `json:"textBody"`
	HTMLBody              string         `json:"htmlBody"`
	Attachments           []Attachment   `json:"attachments"`
	Headers               []Header       `json:"headers"`
	Keywords              []string       `json:"keywords"`
	AuthenticationResults string         `json:"authenticationResults"`
	// SMIME is set for signed or encrypted messages.
	SMIME *SMIMEStatus `json:"smime,omitzero"`
}

// Message wraps one message.
type Message struct {
	Message MessageDetail `json:"message"`
}

// GetThread asks for every message of a conversation.
type GetThread struct {
	ThreadID int64 `json:"-" path:"threadId"`
}

// Flag is a standard message flag.
type Flag string

// Flags a client may set or clear.
const (
	FlagSeen     Flag = "seen"
	FlagAnswered Flag = "answered"
	FlagFlagged  Flag = "flagged"
	FlagDeleted  Flag = "deleted"
	FlagDraft    Flag = "draft"
)

// UpdateFlags sets and clears flags and labels on messages.
type UpdateFlags struct {
	IDs            []int64  `json:"ids"`
	Add            []Flag   `json:"add,omitzero"`
	Remove         []Flag   `json:"remove,omitzero"`
	AddKeywords    []string `json:"addKeywords,omitzero"`
	RemoveKeywords []string `json:"removeKeywords,omitzero"`
}

// Validate checks the ids, flags and labels.
func (u UpdateFlags) Validate() error {
	if err := checkIDs(u.IDs); err != nil {
		return err
	}
	for _, f := range append(append([]Flag(nil), u.Add...), u.Remove...) {
		switch f {
		case FlagSeen, FlagAnswered, FlagFlagged, FlagDeleted, FlagDraft:
		default:
			return invalid("add", fmt.Sprintf("unknown flag %q", f))
		}
	}
	for _, k := range append(append([]string(nil), u.AddKeywords...), u.RemoveKeywords...) {
		if k == "" || len(k) > 64 || strings.ContainsAny(k, " \\()[]{}\"%*") {
			return invalid("addKeywords", fmt.Sprintf("invalid label %q", k))
		}
	}
	return nil
}

// MoveMessages moves messages to a folder.
type MoveMessages struct {
	IDs       []int64 `json:"ids"`
	MailboxID int64   `json:"mailboxId"`
}

// Validate checks the ids.
func (m MoveMessages) Validate() error { return checkIDs(m.IDs) }

// DeleteMessages moves messages to Trash, or removes them for good when they
// already are in Trash or Junk.
type DeleteMessages struct {
	IDs []int64 `json:"ids"`
}

// Validate checks the ids.
func (d DeleteMessages) Validate() error { return checkIDs(d.IDs) }

// Identity is an address the user may send from.
type Identity struct {
	Address     string `json:"address"`
	DisplayName string `json:"displayName"`
}

// ListIdentities asks for the addresses the user may send from.
type ListIdentities struct{}

// Identities lists sending addresses, the account's own first.
type Identities struct {
	Identities []Identity `json:"identities"`
}

// NewAttachment refers to a file uploaded with POST /api/v1/uploads.
type NewAttachment struct {
	UploadID  string `json:"uploadId"`
	ContentID string `json:"contentId,omitzero"` // set for inline images
}

// Compose is a message being written.
type Compose struct {
	From        string          `json:"from,omitzero"` // default: the account's own address
	To          []string        `json:"to,omitzero"`
	Cc          []string        `json:"cc,omitzero"`
	Bcc         []string        `json:"bcc,omitzero"`
	Subject     string          `json:"subject,omitzero"`
	TextBody    string          `json:"textBody,omitzero"`
	HTMLBody    string          `json:"htmlBody,omitzero"`
	InReplyTo   string          `json:"inReplyTo,omitzero"`
	References  []string        `json:"references,omitzero"`
	Attachments []NewAttachment `json:"attachments,omitzero"`
	DraftID     int64           `json:"draftId,omitzero"` // the draft this replaces
}

// SendMessage sends a message and files a copy in Sent.
type SendMessage struct {
	Message Compose `json:"message"`
	// ConfirmSensitive sends after the sender saw a data loss prevention
	// warning (error code policy_warning).
	ConfirmSensitive bool `json:"confirmSensitive,omitzero"`
}

// Validate checks there is someone to send to.
func (s SendMessage) Validate() error {
	if len(s.Message.To)+len(s.Message.Cc)+len(s.Message.Bcc) == 0 {
		return invalid("to", "add at least one recipient")
	}
	return nil
}

// Sent reports where a sent message went.
type Sent struct {
	MessageID        string `json:"messageId"`
	Queued           int    `json:"queued"`
	DeliveredLocally int    `json:"deliveredLocally"`
}

// SaveDraft stores a message in Drafts, replacing DraftID.
type SaveDraft struct {
	Message Compose `json:"message"`
}

// DraftSaved is the stored draft.
type DraftSaved struct {
	DraftID int64 `json:"draftId"`
}

// GetMailSettings asks how mail apps connect.
type GetMailSettings struct{}

// MailEndpoint is one port mail apps can use.
type MailEndpoint struct {
	Protocol string `json:"protocol"` // IMAP, POP3 or SMTP
	Port     int    `json:"port"`
	Security string `json:"security"` // TLS or STARTTLS
}

// MailSettings is what a mail app needs to connect.
type MailSettings struct {
	Hostname  string         `json:"hostname"`
	Endpoints []MailEndpoint `json:"endpoints"`
}

// Watch follows changes to the user's folders.
type Watch struct{}

// Change names the folders that changed. The first event, and one every
// 25 seconds, is empty: it keeps the connection open through gateways.
type Change struct {
	MailboxIDs []int64 `json:"mailboxIds"`
}

// Upload is a file stored for a message being written.
type Upload struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
}

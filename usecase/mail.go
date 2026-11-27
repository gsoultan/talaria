// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// Mail serves the signed-in user's mailboxes and messages.
type Mail struct {
	Store    *store.Store
	Blobs    *blob.Store
	Hub      *hub.Hub
	Submit   *outbound.Submitter
	Deliver  *mail.Deliverer
	Uploads  Uploads
	IP       ClientIP
	Hostname string
	MaxSize  int64
	// Endpoints lists the mail-app listeners, for the settings screen.
	Endpoints  []domain.MailEndpoint
	Quarantine QuarantinePolicy
	// Keepalive is how often Watch sends an empty change; default 25 s,
	// under the idle timeouts of Cloudflare (100 s) and most gateways.
	Keepalive time.Duration
}

func mailboxDTO(m store.Mailbox) domain.Mailbox {
	return domain.Mailbox{ID: m.ID, Name: m.Name, SpecialUse: m.SpecialUse, Total: m.Total, Unread: m.Unread, Size: m.Size, Subscribed: m.Subscribed}
}

// GetMailSettings tells mail apps how to connect.
func (s *Mail) GetMailSettings(context.Context, domain.GetMailSettings) (domain.MailSettings, error) {
	return domain.MailSettings{Hostname: s.Hostname, Endpoints: list(s.Endpoints)}, nil
}

// ListMailboxes returns the user's folders.
func (s *Mail) ListMailboxes(ctx context.Context, _ domain.ListMailboxes) (domain.Mailboxes, error) {
	mbs, err := s.Store.ListMailboxes(ctx, userOf(ctx).ID)
	if err != nil {
		return domain.Mailboxes{}, storeErr(err)
	}
	out := domain.Mailboxes{Mailboxes: make([]domain.Mailbox, len(mbs))}
	for i, m := range mbs {
		out.Mailboxes[i] = mailboxDTO(m)
	}
	return out, nil
}

// CreateMailbox adds a folder.
func (s *Mail) CreateMailbox(ctx context.Context, in domain.CreateMailbox) (domain.MailboxCreated, error) {
	u := userOf(ctx)
	m, err := s.Store.CreateMailbox(ctx, u.ID, in.Name)
	if err != nil {
		return domain.MailboxCreated{}, storeErr(err)
	}
	s.Hub.Publish(u.ID, m.ID)
	return domain.MailboxCreated{Mailbox: mailboxDTO(m)}, nil
}

// RenameMailbox renames a folder.
func (s *Mail) RenameMailbox(ctx context.Context, in domain.RenameMailbox) (domain.Done, error) {
	u := userOf(ctx)
	if err := s.Store.RenameMailbox(ctx, u.ID, in.ID, in.Name); err != nil {
		return domain.Done{}, storeErr(err)
	}
	s.Hub.Publish(u.ID, in.ID)
	return domain.Done{}, nil
}

// DeleteMailbox removes a folder.
func (s *Mail) DeleteMailbox(ctx context.Context, in domain.DeleteMailbox) (domain.Done, error) {
	u := userOf(ctx)
	if err := s.Store.DeleteMailbox(ctx, u.ID, in.ID); err != nil {
		return domain.Done{}, storeErr(err)
	}
	s.Hub.Publish(u.ID, in.ID)
	return domain.Done{}, nil
}

func encodeCursor(m store.Message) string {
	return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%d", m.InternalDate, m.ID))
}

func decodeCursor(c string) (date, id int64, err error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, 0, err
	}
	d, i, ok := strings.Cut(string(b), ":")
	if !ok {
		return 0, 0, errors.New("bad cursor")
	}
	if date, err = strconv.ParseInt(d, 10, 64); err != nil {
		return 0, 0, err
	}
	id, err = strconv.ParseInt(i, 10, 64)
	return date, id, err
}

// ListMessages returns a page of a folder.
func (s *Mail) ListMessages(ctx context.Context, in domain.ListMessages) (domain.MessagePage, error) {
	u := userOf(ctx)
	mb, err := s.Store.Mailbox(ctx, u.ID, in.MailboxID)
	if err != nil {
		return domain.MessagePage{}, storeErr(err)
	}
	o := store.ListOptions{Limit: in.Limit, UnreadOnly: in.UnreadOnly, FlaggedOnly: in.FlaggedOnly}
	if o.Limit <= 0 || o.Limit > 200 {
		o.Limit = 50
	}
	if in.Cursor != "" {
		if o.BeforeDate, o.BeforeID, err = decodeCursor(in.Cursor); err != nil {
			return domain.MessagePage{}, kakarot.Invalid("bad cursor", map[string]string{"cursor": "bad cursor"})
		}
	}
	msgs, err := s.Store.ListMessages(ctx, u.ID, mb.ID, o)
	if err != nil {
		return domain.MessagePage{}, storeErr(err)
	}
	out := domain.MessagePage{Messages: summaries(msgs), HighestModSeq: mb.HighestModSeq}
	if len(msgs) == o.Limit {
		out.NextCursor = encodeCursor(msgs[len(msgs)-1])
	}
	return out, nil
}

// Search finds messages.
func (s *Mail) Search(ctx context.Context, in domain.Search) (domain.Messages, error) {
	msgs, err := s.Store.Search(ctx, userOf(ctx).ID, in.Query, store.SearchOptions{
		MailboxID: in.MailboxID, From: in.From, Unread: in.Unread, Flagged: in.Flagged, HasAttach: in.HasAttachments,
		After: in.After, Before: in.Before, Limit: in.Limit,
	})
	if err != nil {
		return domain.Messages{}, storeErr(err)
	}
	return domain.Messages{Messages: summaries(msgs)}, nil
}

// GetMessage returns a message with its body. Reading it does not mark it
// seen; the client does that with UpdateFlags.
func (s *Mail) GetMessage(ctx context.Context, in domain.GetMessage) (domain.Message, error) {
	u := userOf(ctx)
	m, err := s.Store.Message(ctx, u.ID, in.ID)
	if err != nil {
		return domain.Message{}, storeErr(err)
	}
	r, err := s.Blobs.Open(u.TenantID, m.BlobHash)
	if err != nil {
		return domain.Message{}, internal(err)
	}
	d, err := mail.ReadDetail(r)
	r.Close()
	if err != nil && d.Text == "" && d.HTML == "" {
		return domain.Message{}, internal(err)
	}
	kw, _ := s.Store.Keywords(ctx, m.ID)
	out := domain.MessageDetail{
		Summary: summary(m), MessageID: m.MessageID, InReplyTo: m.InReplyTo, ReplyTo: d.ReplyTo,
		TextBody: d.Text, HTMLBody: d.HTML, Keywords: list(kw), AuthenticationResults: d.AuthResults,
		Headers: make([]domain.Header, 0, len(d.Headers)), Attachments: make([]domain.Attachment, 0, len(d.Parts)),
	}
	for _, h := range d.Headers {
		out.Headers = append(out.Headers, domain.Header{Name: h[0], Value: h[1]})
	}
	for _, p := range d.Parts {
		out.Attachments = append(out.Attachments, domain.Attachment{Part: p.Path, Filename: p.Filename, ContentType: p.ContentType,
			Size: p.Size, ContentID: p.ContentID, Inline: p.Inline})
	}
	return domain.Message{Message: out}, nil
}

// GetThread returns a conversation, oldest first.
func (s *Mail) GetThread(ctx context.Context, in domain.GetThread) (domain.Messages, error) {
	msgs, err := s.Store.Thread(ctx, userOf(ctx).ID, in.ThreadID)
	if err != nil {
		return domain.Messages{}, storeErr(err)
	}
	return domain.Messages{Messages: summaries(msgs)}, nil
}

var flagBits = map[domain.Flag]store.Flag{
	domain.FlagSeen: store.FlagSeen, domain.FlagAnswered: store.FlagAnswered, domain.FlagFlagged: store.FlagFlagged,
	domain.FlagDeleted: store.FlagDeleted, domain.FlagDraft: store.FlagDraft,
}

// UpdateFlags sets and clears flags and labels.
func (s *Mail) UpdateFlags(ctx context.Context, in domain.UpdateFlags) (domain.Done, error) {
	u := userOf(ctx)
	var add, remove store.Flag
	for _, f := range in.Add {
		add |= flagBits[f]
	}
	for _, f := range in.Remove {
		remove |= flagBits[f]
	}
	if add != 0 || remove != 0 {
		mbs, err := s.Store.SetFlags(ctx, u.ID, in.IDs, add, remove)
		if err != nil {
			return domain.Done{}, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	if len(in.AddKeywords) > 0 || len(in.RemoveKeywords) > 0 {
		if err := s.Store.SetKeywords(ctx, u.ID, in.IDs, in.AddKeywords, in.RemoveKeywords); err != nil {
			return domain.Done{}, storeErr(err)
		}
	}
	return domain.Done{}, nil
}

// MoveMessages moves messages to another folder.
func (s *Mail) MoveMessages(ctx context.Context, in domain.MoveMessages) (domain.Done, error) {
	u := userOf(ctx)
	mbs, err := s.Store.MoveMessages(ctx, u.ID, in.IDs, in.MailboxID)
	if err != nil {
		return domain.Done{}, storeErr(err)
	}
	s.Hub.Publish(u.ID, mbs...)
	return domain.Done{}, nil
}

// DeleteMessages moves messages to Trash, or removes them from Trash and
// Junk for good.
func (s *Mail) DeleteMessages(ctx context.Context, in domain.DeleteMessages) (domain.Done, error) {
	u := userOf(ctx)
	trash, err := s.Store.MailboxByUse(ctx, u.ID, store.UseTrash)
	if err != nil {
		return domain.Done{}, storeErr(err)
	}
	junk, _ := s.Store.MailboxByUse(ctx, u.ID, store.UseJunk)
	var purge, move []int64
	for _, id := range in.IDs {
		m, err := s.Store.Message(ctx, u.ID, id)
		if err != nil {
			continue
		}
		if m.MailboxID == trash.ID || m.MailboxID == junk.ID {
			purge = append(purge, id)
		} else {
			move = append(move, id)
		}
	}
	if len(move) > 0 {
		mbs, err := s.Store.MoveMessages(ctx, u.ID, move, trash.ID)
		if err != nil {
			return domain.Done{}, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	if len(purge) > 0 {
		mbs, err := s.Store.ExpungeMessages(ctx, u.ID, purge)
		if err != nil {
			return domain.Done{}, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	return domain.Done{}, nil
}

// Watch streams the ids of folders that change, until the client leaves.
func (s *Mail) Watch(ctx context.Context, _ domain.Watch) iter.Seq2[domain.Change, error] {
	return func(yield func(domain.Change, error) bool) {
		events, cancel := s.Hub.Subscribe(userOf(ctx).ID)
		defer cancel()
		every := s.Keepalive
		if every <= 0 {
			every = 25 * time.Second
		}
		t := time.NewTicker(every)
		defer t.Stop()
		// An empty first event opens the stream at once.
		if !yield(domain.Change{MailboxIDs: []int64{}}, nil) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				if !yield(domain.Change{MailboxIDs: list(ev.MailboxIDs)}, nil) {
					return
				}
			case <-t.C:
				if !yield(domain.Change{MailboxIDs: []int64{}}, nil) {
					return
				}
			}
		}
	}
}

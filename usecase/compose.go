// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	gomail "github.com/emersion/go-message/mail"
	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// ListIdentities returns the addresses the user may send from.
func (s *Mail) ListIdentities(ctx context.Context, _ domain.ListIdentities) (domain.Identities, error) {
	u := userOf(ctx)
	out := domain.Identities{Identities: []domain.Identity{{Address: u.Address(), DisplayName: u.DisplayName}}}
	as, err := s.Store.ListAliases(ctx, u.TenantID, u.ID)
	if err != nil {
		return domain.Identities{}, storeErr(err)
	}
	for _, a := range as {
		out.Identities = append(out.Identities, domain.Identity{Address: a.Address, DisplayName: u.DisplayName})
	}
	return out, nil
}

func (s *Mail) newMessageID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b) + "@" + s.Hostname
}

func badField(field string, err error) error {
	return kakarot.Invalid(err.Error(), map[string]string{field: err.Error()})
}

// build turns a Compose into a message.
func (s *Mail) build(ctx context.Context, u store.User, c domain.Compose, keepBcc bool) (*mail.Compose, error) {
	from := &gomail.Address{Name: u.DisplayName, Address: u.Address()}
	if c.From != "" {
		as, err := mail.ParseAddresses([]string{c.From})
		if err != nil || len(as) != 1 {
			return nil, badField("from", errors.New("invalid from address"))
		}
		if !s.Store.CanSendAs(ctx, u, as[0].Address) {
			return nil, kakarot.E(kakarot.CodeForbidden, outbound.ErrSenderNotAllowed.Error(), nil)
		}
		from = as[0]
		if from.Name == "" {
			from.Name = u.DisplayName
		}
	}
	to, err := mail.ParseAddresses(c.To)
	if err != nil {
		return nil, badField("to", err)
	}
	cc, err := mail.ParseAddresses(c.Cc)
	if err != nil {
		return nil, badField("cc", err)
	}
	bcc, err := mail.ParseAddresses(c.Bcc)
	if err != nil {
		return nil, badField("bcc", err)
	}
	m := &mail.Compose{From: from, To: to, Cc: cc, Bcc: bcc, Subject: c.Subject, Text: c.TextBody, HTML: c.HTMLBody,
		InReplyTo: c.InReplyTo, References: c.References, MessageID: s.newMessageID(), KeepBcc: keepBcc}
	var total int64
	for _, a := range c.Attachments {
		up, data, err := s.Uploads.Read(ctx, u.ID, a.UploadID)
		if err != nil {
			return nil, kakarot.E(kakarot.CodeInvalid, "an attachment is no longer on the server; attach it again", err)
		}
		total += int64(len(data))
		m.Attachments = append(m.Attachments, mail.NewAttachment{Filename: up.Filename, ContentType: up.ContentType, ContentID: a.ContentID, Data: data})
	}
	if s.MaxSize > 0 && total*4/3 > s.MaxSize {
		return nil, kakarot.E(kakarot.CodeInvalid, "attachments are too large", mail.ErrTooLarge)
	}
	return m, nil
}

// SendMessage sends a message.
func (s *Mail) SendMessage(ctx context.Context, in domain.SendMessage) (domain.Sent, error) {
	u := userOf(ctx)
	c, err := s.build(ctx, u, in.Message, false)
	if err != nil {
		return domain.Sent{}, err
	}
	var rcpts []string
	for _, l := range [][]*gomail.Address{c.To, c.Cc, c.Bcc} {
		for _, a := range l {
			rcpts = append(rcpts, a.Address)
		}
	}
	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		return domain.Sent{}, internal(err)
	}
	res, err := s.Submit.Submit(ctx, outbound.Submission{User: u, MailFrom: c.From.Address, Rcpts: rcpts, SaveSent: true,
		ClientIP: s.IP(ctx), Proto: "HTTPS"}, &buf)
	var rerr *outbound.RecipientError
	switch {
	case err == nil:
	case errors.As(err, &rerr):
		return domain.Sent{}, badField("to", err)
	default:
		return domain.Sent{}, storeErr(err)
	}
	if c.InReplyTo != "" {
		if orig, err := s.Store.MessageByMessageID(ctx, u.ID, c.InReplyTo); err == nil {
			if mbs, err := s.Store.SetFlags(ctx, u.ID, []int64{orig.ID}, store.FlagAnswered, 0); err == nil {
				s.Hub.Publish(u.ID, mbs...)
			}
		}
	}
	s.dropDraft(ctx, u, in.Message.DraftID)
	return domain.Sent{MessageID: c.MessageID, Queued: res.Queued, DeliveredLocally: res.Local}, nil
}

// SaveDraft stores the message in Drafts, replacing the earlier draft.
func (s *Mail) SaveDraft(ctx context.Context, in domain.SaveDraft) (domain.DraftSaved, error) {
	u := userOf(ctx)
	c, err := s.build(ctx, u, in.Message, true)
	if err != nil {
		return domain.DraftSaved{}, err
	}
	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		return domain.DraftSaved{}, internal(err)
	}
	var id int64
	_, err = s.Deliver.Deliver(ctx, mail.Inbound{Rcpts: []store.User{u}, Trusted: true, MailboxUse: store.UseDrafts,
		Flags: store.FlagDraft | store.FlagSeen, Stored: func(m store.Message) { id = m.ID }}, &buf)
	if err != nil {
		return domain.DraftSaved{}, storeErr(err)
	}
	s.dropDraft(ctx, u, in.Message.DraftID)
	return domain.DraftSaved{DraftID: id}, nil
}

// dropDraft removes a superseded draft, only if it really is in Drafts.
func (s *Mail) dropDraft(ctx context.Context, u store.User, id int64) {
	if id == 0 {
		return
	}
	m, err := s.Store.Message(ctx, u.ID, id)
	if err != nil {
		return
	}
	drafts, err := s.Store.MailboxByUse(ctx, u.ID, store.UseDrafts)
	if err != nil || m.MailboxID != drafts.ID {
		return
	}
	if mbs, err := s.Store.ExpungeMessages(ctx, u.ID, []int64{id}); err == nil {
		s.Hub.Publish(u.ID, mbs...)
	}
}

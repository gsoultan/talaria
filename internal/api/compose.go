// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	gomail "github.com/emersion/go-message/mail"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

func (s *MailServer) ListIdentities(ctx context.Context, _ *connect.Request[talariav1.ListIdentitiesRequest]) (*connect.Response[talariav1.ListIdentitiesResponse], error) {
	u := UserFrom(ctx)
	res := &talariav1.ListIdentitiesResponse{Identities: []*talariav1.Identity{{Address: u.Address(), DisplayName: u.DisplayName}}}
	as, err := s.Store.ListAliases(ctx, u.TenantID, u.ID)
	if err != nil {
		return nil, storeErr(err)
	}
	for _, a := range as {
		res.Identities = append(res.Identities, &talariav1.Identity{Address: a.Address, DisplayName: u.DisplayName})
	}
	return connect.NewResponse(res), nil
}

func (s *MailServer) newMessageID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b) + "@" + s.Hostname
}

// build turns a Compose request into a message.
func (s *MailServer) build(ctx context.Context, u store.User, c *talariav1.Compose, keepBcc bool) (*mail.Compose, error) {
	if c == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("message is required"))
	}
	bad := func(err error) error { return connect.NewError(connect.CodeInvalidArgument, err) }
	from := &gomail.Address{Name: u.DisplayName, Address: u.Address()}
	if c.From != "" {
		as, err := mail.ParseAddresses([]string{c.From})
		if err != nil || len(as) != 1 {
			return nil, bad(fmt.Errorf("invalid from address"))
		}
		if !s.Store.CanSendAs(ctx, u, as[0].Address) {
			return nil, connect.NewError(connect.CodePermissionDenied, outbound.ErrSenderNotAllowed)
		}
		from = as[0]
		if from.Name == "" {
			from.Name = u.DisplayName
		}
	}
	to, err := mail.ParseAddresses(c.To)
	if err != nil {
		return nil, bad(err)
	}
	cc, err := mail.ParseAddresses(c.Cc)
	if err != nil {
		return nil, bad(err)
	}
	bcc, err := mail.ParseAddresses(c.Bcc)
	if err != nil {
		return nil, bad(err)
	}
	m := &mail.Compose{From: from, To: to, Cc: cc, Bcc: bcc, Subject: c.Subject, Text: c.TextBody, HTML: c.HtmlBody,
		InReplyTo: c.InReplyTo, References: c.References, MessageID: s.newMessageID(), KeepBcc: keepBcc}
	var total int64
	for _, a := range c.Attachments {
		total += int64(len(a.Data))
		m.Attachments = append(m.Attachments, mail.NewAttachment{Filename: a.Filename, ContentType: a.ContentType, ContentID: a.ContentId, Data: a.Data})
	}
	if s.MaxSize > 0 && total*4/3 > s.MaxSize {
		return nil, connect.NewError(connect.CodeInvalidArgument, mail.ErrTooLarge)
	}
	return m, nil
}

func (s *MailServer) SendMessage(ctx context.Context, req *connect.Request[talariav1.SendMessageRequest]) (*connect.Response[talariav1.SendMessageResponse], error) {
	u := UserFrom(ctx)
	c, err := s.build(ctx, u, req.Msg.Message, false)
	if err != nil {
		return nil, err
	}
	var rcpts []string
	for _, l := range [][]*gomail.Address{c.To, c.Cc, c.Bcc} {
		for _, a := range l {
			rcpts = append(rcpts, a.Address)
		}
	}
	if len(rcpts) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("add at least one recipient"))
	}
	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		return nil, internal(err)
	}
	res, err := s.Submit.Submit(ctx, outbound.Submission{User: u, MailFrom: c.From.Address, Rcpts: rcpts, SaveSent: true,
		ClientIP: clientip.From(ctx).String(), Proto: "HTTPS"}, &buf)
	var rerr *outbound.RecipientError
	switch {
	case err == nil:
	case errors.As(err, &rerr):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, outbound.ErrSenderNotAllowed):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, store.ErrSendLimit), errors.Is(err, store.ErrQuotaExceeded):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, mail.ErrTooLarge):
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return nil, internal(err)
	}
	if c.InReplyTo != "" {
		if orig, err := s.Store.MessageByMessageID(ctx, u.ID, c.InReplyTo); err == nil {
			if mbs, err := s.Store.SetFlags(ctx, u.ID, []int64{orig.ID}, store.FlagAnswered, 0); err == nil {
				s.Hub.Publish(u.ID, mbs...)
			}
		}
	}
	s.dropDraft(ctx, u, req.Msg.Message.DraftId)
	return connect.NewResponse(&talariav1.SendMessageResponse{MessageId: c.MessageID, Queued: int32(res.Queued), DeliveredLocally: int32(res.Local)}), nil
}

func (s *MailServer) SaveDraft(ctx context.Context, req *connect.Request[talariav1.SaveDraftRequest]) (*connect.Response[talariav1.SaveDraftResponse], error) {
	u := UserFrom(ctx)
	c, err := s.build(ctx, u, req.Msg.Message, true)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		return nil, internal(err)
	}
	var id int64
	_, err = s.Deliver.Deliver(ctx, mail.Inbound{Rcpts: []store.User{u}, Trusted: true, MailboxUse: store.UseDrafts,
		Flags: store.FlagDraft | store.FlagSeen, Stored: func(m store.Message) { id = m.ID }}, &buf)
	if err != nil {
		return nil, storeErr(err)
	}
	s.dropDraft(ctx, u, req.Msg.Message.DraftId)
	return connect.NewResponse(&talariav1.SaveDraftResponse{DraftId: id}), nil
}

// dropDraft removes a superseded draft, only if it really is in Drafts.
func (s *MailServer) dropDraft(ctx context.Context, u store.User, id int64) {
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

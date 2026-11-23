// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// MailServer implements talaria.v1.MailService for the signed-in user.
type MailServer struct {
	Store *store.Store
	Blobs *blob.Store
	Hub   *hub.Hub
}

var _ talariav1connect.MailServiceHandler = (*MailServer)(nil)

func mailboxToProto(m store.Mailbox) *talariav1.Mailbox {
	return &talariav1.Mailbox{Id: m.ID, Name: m.Name, SpecialUse: m.SpecialUse, Total: m.Total, Unread: m.Unread, Size: m.Size, Subscribed: m.Subscribed}
}

func (s *MailServer) ListMailboxes(ctx context.Context, _ *connect.Request[talariav1.ListMailboxesRequest]) (*connect.Response[talariav1.ListMailboxesResponse], error) {
	mbs, err := s.Store.ListMailboxes(ctx, UserFrom(ctx).ID)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListMailboxesResponse{Mailboxes: make([]*talariav1.Mailbox, len(mbs))}
	for i, m := range mbs {
		res.Mailboxes[i] = mailboxToProto(m)
	}
	return connect.NewResponse(res), nil
}

func (s *MailServer) CreateMailbox(ctx context.Context, req *connect.Request[talariav1.CreateMailboxRequest]) (*connect.Response[talariav1.CreateMailboxResponse], error) {
	u := UserFrom(ctx)
	m, err := s.Store.CreateMailbox(ctx, u.ID, req.Msg.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	s.Hub.Publish(u.ID, m.ID)
	return connect.NewResponse(&talariav1.CreateMailboxResponse{Mailbox: mailboxToProto(m)}), nil
}

func (s *MailServer) RenameMailbox(ctx context.Context, req *connect.Request[talariav1.RenameMailboxRequest]) (*connect.Response[talariav1.RenameMailboxResponse], error) {
	u := UserFrom(ctx)
	if err := s.Store.RenameMailbox(ctx, u.ID, req.Msg.Id, req.Msg.Name); err != nil {
		return nil, storeErr(err)
	}
	s.Hub.Publish(u.ID, req.Msg.Id)
	return connect.NewResponse(&talariav1.RenameMailboxResponse{}), nil
}

func (s *MailServer) DeleteMailbox(ctx context.Context, req *connect.Request[talariav1.DeleteMailboxRequest]) (*connect.Response[talariav1.DeleteMailboxResponse], error) {
	u := UserFrom(ctx)
	if err := s.Store.DeleteMailbox(ctx, u.ID, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	s.Hub.Publish(u.ID, req.Msg.Id)
	return connect.NewResponse(&talariav1.DeleteMailboxResponse{}), nil
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

func (s *MailServer) ListMessages(ctx context.Context, req *connect.Request[talariav1.ListMessagesRequest]) (*connect.Response[talariav1.ListMessagesResponse], error) {
	u := UserFrom(ctx)
	mb, err := s.Store.Mailbox(ctx, u.ID, req.Msg.MailboxId)
	if err != nil {
		return nil, storeErr(err)
	}
	o := store.ListOptions{Limit: int(req.Msg.Limit), UnreadOnly: req.Msg.UnreadOnly, FlaggedOnly: req.Msg.FlaggedOnly}
	if o.Limit <= 0 || o.Limit > 200 {
		o.Limit = 50
	}
	if req.Msg.Cursor != "" {
		if o.BeforeDate, o.BeforeID, err = decodeCursor(req.Msg.Cursor); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad cursor"))
		}
	}
	msgs, err := s.Store.ListMessages(ctx, u.ID, mb.ID, o)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListMessagesResponse{Messages: summaries(msgs), HighestModseq: mb.HighestModSeq}
	if len(msgs) == o.Limit {
		res.NextCursor = encodeCursor(msgs[len(msgs)-1])
	}
	return connect.NewResponse(res), nil
}

func (s *MailServer) Search(ctx context.Context, req *connect.Request[talariav1.SearchRequest]) (*connect.Response[talariav1.SearchResponse], error) {
	m := req.Msg
	msgs, err := s.Store.Search(ctx, UserFrom(ctx).ID, m.Query, store.SearchOptions{
		MailboxID: m.MailboxId, From: m.From, Unread: m.Unread, Flagged: m.Flagged, HasAttach: m.HasAttachments,
		After: m.After, Before: m.Before, Limit: int(m.Limit),
	})
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.SearchResponse{Messages: summaries(msgs)}), nil
}

func (s *MailServer) GetMessage(ctx context.Context, req *connect.Request[talariav1.GetMessageRequest]) (*connect.Response[talariav1.GetMessageResponse], error) {
	u := UserFrom(ctx)
	m, err := s.Store.Message(ctx, u.ID, req.Msg.Id)
	if err != nil {
		return nil, storeErr(err)
	}
	r, err := s.Blobs.Open(u.TenantID, m.BlobHash)
	if err != nil {
		return nil, internal(err)
	}
	d, err := mail.ReadDetail(r)
	r.Close()
	if err != nil && d.Text == "" && d.HTML == "" {
		return nil, internal(err)
	}
	if req.Msg.MarkSeen && m.Flags&store.FlagSeen == 0 {
		if mbs, err := s.Store.SetFlags(ctx, u.ID, []int64{m.ID}, store.FlagSeen, 0); err == nil {
			m.Flags |= store.FlagSeen
			s.Hub.Publish(u.ID, mbs...)
		}
	}
	kw, _ := s.Store.Keywords(ctx, m.ID)
	out := &talariav1.MessageDetail{
		Summary: summaryToProto(m), MessageId: m.MessageID, InReplyTo: m.InReplyTo, ReplyTo: d.ReplyTo,
		TextBody: d.Text, HtmlBody: d.HTML, Keywords: kw, AuthenticationResults: d.AuthResults,
	}
	for _, h := range d.Headers {
		out.Headers = append(out.Headers, &talariav1.Header{Name: h[0], Value: h[1]})
	}
	for _, p := range d.Parts {
		out.Attachments = append(out.Attachments, &talariav1.Attachment{Part: p.Path, Filename: p.Filename, ContentType: p.ContentType,
			Size: p.Size, ContentId: p.ContentID, Inline: p.Inline})
	}
	return connect.NewResponse(&talariav1.GetMessageResponse{Message: out}), nil
}

func (s *MailServer) GetThread(ctx context.Context, req *connect.Request[talariav1.GetThreadRequest]) (*connect.Response[talariav1.GetThreadResponse], error) {
	msgs, err := s.Store.Thread(ctx, UserFrom(ctx).ID, req.Msg.ThreadId)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.GetThreadResponse{Messages: summaries(msgs)}), nil
}

const maxBatch = 1000

func checkIDs(ids []int64) error {
	if len(ids) == 0 || len(ids) > maxBatch {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("give 1 to %d message ids", maxBatch))
	}
	return nil
}

func (s *MailServer) UpdateFlags(ctx context.Context, req *connect.Request[talariav1.UpdateFlagsRequest]) (*connect.Response[talariav1.UpdateFlagsResponse], error) {
	u := UserFrom(ctx)
	if err := checkIDs(req.Msg.Ids); err != nil {
		return nil, err
	}
	var add, remove store.Flag
	for _, f := range req.Msg.Add {
		add |= flagFromProto(f)
	}
	for _, f := range req.Msg.Remove {
		remove |= flagFromProto(f)
	}
	if add != 0 || remove != 0 {
		mbs, err := s.Store.SetFlags(ctx, u.ID, req.Msg.Ids, add, remove)
		if err != nil {
			return nil, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	if len(req.Msg.AddKeywords) > 0 || len(req.Msg.RemoveKeywords) > 0 {
		for _, k := range append(append([]string(nil), req.Msg.AddKeywords...), req.Msg.RemoveKeywords...) {
			if k == "" || len(k) > 64 || strings.ContainsAny(k, " \\()[]{}\"%*") {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid label %q", k))
			}
		}
		if err := s.Store.SetKeywords(ctx, u.ID, req.Msg.Ids, req.Msg.AddKeywords, req.Msg.RemoveKeywords); err != nil {
			return nil, storeErr(err)
		}
	}
	return connect.NewResponse(&talariav1.UpdateFlagsResponse{}), nil
}

func (s *MailServer) MoveMessages(ctx context.Context, req *connect.Request[talariav1.MoveMessagesRequest]) (*connect.Response[talariav1.MoveMessagesResponse], error) {
	u := UserFrom(ctx)
	if err := checkIDs(req.Msg.Ids); err != nil {
		return nil, err
	}
	mbs, err := s.Store.MoveMessages(ctx, u.ID, req.Msg.Ids, req.Msg.MailboxId)
	if err != nil {
		return nil, storeErr(err)
	}
	s.Hub.Publish(u.ID, mbs...)
	return connect.NewResponse(&talariav1.MoveMessagesResponse{}), nil
}

func (s *MailServer) DeleteMessages(ctx context.Context, req *connect.Request[talariav1.DeleteMessagesRequest]) (*connect.Response[talariav1.DeleteMessagesResponse], error) {
	u := UserFrom(ctx)
	if err := checkIDs(req.Msg.Ids); err != nil {
		return nil, err
	}
	trash, err := s.Store.MailboxByUse(ctx, u.ID, store.UseTrash)
	if err != nil {
		return nil, storeErr(err)
	}
	junk, _ := s.Store.MailboxByUse(ctx, u.ID, store.UseJunk)
	var purge, move []int64
	for _, id := range req.Msg.Ids {
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
			return nil, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	if len(purge) > 0 {
		mbs, err := s.Store.ExpungeMessages(ctx, u.ID, purge)
		if err != nil {
			return nil, storeErr(err)
		}
		s.Hub.Publish(u.ID, mbs...)
	}
	return connect.NewResponse(&talariav1.DeleteMessagesResponse{}), nil
}

// keepalive stays under the idle timeouts of Cloudflare (100 s) and most
// gateways.
const keepalive = 25 * time.Second

func (s *MailServer) Watch(ctx context.Context, _ *connect.Request[talariav1.WatchRequest], stream *connect.ServerStream[talariav1.WatchResponse]) error {
	events, cancel := s.Hub.Subscribe(UserFrom(ctx).ID)
	defer cancel()
	t := time.NewTicker(keepalive)
	defer t.Stop()
	if err := stream.Send(&talariav1.WatchResponse{}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-events:
			if err := stream.Send(&talariav1.WatchResponse{MailboxIds: ev.MailboxIDs}); err != nil {
				return err
			}
		case <-t.C:
			if err := stream.Send(&talariav1.WatchResponse{}); err != nil {
				return err
			}
		}
	}
}

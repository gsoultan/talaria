// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package imapd

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/store"
)

func sprintf(format string, v ...any) string { return fmt.Sprintf(format, v...) }

const delim = '/'

type session struct {
	b      *Backend
	ip     string
	user   *store.User
	events <-chan hub.Event
	unsub  func()
	sel    *selected
}

// selected is the session's view of the selected mailbox: the UIDs it has
// announced, in sequence order.
type selected struct {
	mb       store.Mailbox
	readOnly bool
	uids     []imap.UID
	ids      map[imap.UID]int64
	modseq   int64
	// pending expunges, held back while the client may not receive them.
	searchRes imap.UIDSet
}

var _ imapserver.SessionIMAP4rev2 = (*session)(nil)

func (s *session) Close() error {
	if s.unsub != nil {
		s.unsub()
	}
	return nil
}

func (s *session) Login(username, password string) error {
	if !s.b.fails.Allowed(s.ip) {
		return errTryLater
	}
	u, err := s.b.store.UserByAddress(ctx(), username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return errServer
	}
	if !auth.CheckPassword(u.PasswordHash, password) || u.Suspended {
		s.b.fails.Fail(s.ip)
		return imapserver.ErrAuthFailed
	}
	s.user = &u
	s.events, s.unsub = s.b.hub.Subscribe(u.ID)
	return nil
}

// name maps an IMAP mailbox name to the stored one (INBOX is case-insensitive).
func name(n string) string {
	n = strings.Trim(n, "/")
	if strings.EqualFold(n, "INBOX") {
		return "INBOX"
	}
	if len(n) > 6 && strings.EqualFold(n[:6], "INBOX/") {
		return "INBOX" + n[5:]
	}
	return n
}

func (s *session) mailbox(n string) (store.Mailbox, error) {
	mb, err := s.b.store.MailboxByName(ctx(), s.user.ID, name(n))
	if err != nil {
		return mb, s.b.err(err)
	}
	return mb, nil
}

func useAttr(use string) []imap.MailboxAttr {
	switch use {
	case store.UseSent:
		return []imap.MailboxAttr{imap.MailboxAttrSent}
	case store.UseDrafts:
		return []imap.MailboxAttr{imap.MailboxAttrDrafts}
	case store.UseJunk:
		return []imap.MailboxAttr{imap.MailboxAttrJunk}
	case store.UseTrash:
		return []imap.MailboxAttr{imap.MailboxAttrTrash}
	case store.UseArchive:
		return []imap.MailboxAttr{imap.MailboxAttrArchive}
	}
	return nil
}

var systemFlags = []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft}

func (s *session) Select(n string, options *imap.SelectOptions) (*imap.SelectData, error) {
	mb, err := s.mailbox(n)
	if err != nil {
		return nil, err
	}
	msgs, err := s.b.store.MailboxMessages(ctx(), s.user.ID, mb.ID)
	if err != nil {
		return nil, s.b.err(err)
	}
	sel := &selected{mb: mb, readOnly: options != nil && options.ReadOnly, ids: make(map[imap.UID]int64, len(msgs)), modseq: mb.HighestModSeq}
	var firstUnseen uint32
	for i, m := range msgs {
		sel.uids = append(sel.uids, imap.UID(m.UID))
		sel.ids[imap.UID(m.UID)] = m.ID
		if firstUnseen == 0 && m.Flags&store.FlagSeen == 0 {
			firstUnseen = uint32(i + 1)
		}
	}
	s.sel = sel
	flags := append([]imap.Flag(nil), systemFlags...)
	perm := append(append([]imap.Flag(nil), systemFlags...), imap.FlagWildcard)
	if sel.readOnly {
		perm = nil
	}
	return &imap.SelectData{
		Flags: flags, PermanentFlags: perm, NumMessages: uint32(len(msgs)), FirstUnseenSeqNum: firstUnseen,
		UIDNext: imap.UID(mb.UIDNext), UIDValidity: uint32(mb.UIDValidity),
	}, nil
}

func (s *session) Unselect() error {
	s.sel = nil
	return nil
}

func (s *session) Create(n string, _ *imap.CreateOptions) error {
	n = name(n)
	// Create missing parents, as clients expect.
	parts := strings.Split(n, string(delim))
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], string(delim))
		if _, err := s.b.store.MailboxByName(ctx(), s.user.ID, parent); errors.Is(err, store.ErrNotFound) {
			if _, err := s.b.store.CreateMailbox(ctx(), s.user.ID, parent); err != nil && !errors.Is(err, store.ErrExists) {
				return s.b.err(err)
			}
		}
	}
	mb, err := s.b.store.CreateMailbox(ctx(), s.user.ID, n)
	if err != nil {
		return s.b.err(err)
	}
	s.b.hub.Publish(s.user.ID, mb.ID)
	return nil
}

func (s *session) Delete(n string) error {
	mb, err := s.mailbox(n)
	if err != nil {
		return err
	}
	if err := s.b.store.DeleteMailbox(ctx(), s.user.ID, mb.ID); err != nil {
		return s.b.err(err)
	}
	s.b.hub.Publish(s.user.ID, mb.ID)
	return nil
}

func (s *session) Rename(oldName, newName string, _ *imap.RenameOptions) error {
	mb, err := s.mailbox(oldName)
	if err != nil {
		return err
	}
	if err := s.b.store.RenameMailbox(ctx(), s.user.ID, mb.ID, name(newName)); err != nil {
		return s.b.err(err)
	}
	s.b.hub.Publish(s.user.ID, mb.ID)
	return nil
}

func (s *session) Subscribe(n string) error   { return s.subscribe(n, true) }
func (s *session) Unsubscribe(n string) error { return s.subscribe(n, false) }

func (s *session) subscribe(n string, on bool) error {
	mb, err := s.mailbox(n)
	if err != nil {
		return err
	}
	return s.b.err(s.b.store.SetSubscribed(ctx(), s.user.ID, mb.ID, on))
}

func (s *session) Namespace() (*imap.NamespaceData, error) {
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Prefix: "", Delim: delim}}}, nil
}

func (s *session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	if len(patterns) == 0 {
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: delim})
	}
	mbs, err := s.b.store.ListMailboxes(ctx(), s.user.ID)
	if err != nil {
		return s.b.err(err)
	}
	hasChildren := map[string]bool{}
	for _, mb := range mbs {
		if i := strings.LastIndexByte(mb.Name, byte(delim)); i > 0 {
			hasChildren[mb.Name[:i]] = true
		}
	}
	sort.Slice(mbs, func(i, j int) bool {
		if (mbs[i].Name == "INBOX") != (mbs[j].Name == "INBOX") {
			return mbs[i].Name == "INBOX"
		}
		return mbs[i].Name < mbs[j].Name
	})
	for _, mb := range mbs {
		match := false
		for _, p := range patterns {
			if imapserver.MatchList(mb.Name, delim, ref, p) {
				match = true
				break
			}
		}
		if !match || (options.SelectSubscribed && !mb.Subscribed) || (options.SelectSpecialUse && mb.SpecialUse == "") {
			continue
		}
		data := imap.ListData{Mailbox: mb.Name, Delim: delim}
		if mb.Subscribed {
			data.Attrs = append(data.Attrs, imap.MailboxAttrSubscribed)
		}
		if hasChildren[mb.Name] {
			data.Attrs = append(data.Attrs, imap.MailboxAttrHasChildren)
		} else {
			data.Attrs = append(data.Attrs, imap.MailboxAttrHasNoChildren)
		}
		data.Attrs = append(data.Attrs, useAttr(mb.SpecialUse)...)
		if options.ReturnStatus != nil {
			data.Status = statusData(mb, options.ReturnStatus)
		}
		if err := w.WriteList(&data); err != nil {
			return err
		}
	}
	return nil
}

func statusData(mb store.Mailbox, o *imap.StatusOptions) *imap.StatusData {
	d := &imap.StatusData{Mailbox: mb.Name}
	if o.NumMessages {
		n := uint32(mb.Total)
		d.NumMessages = &n
	}
	if o.UIDNext {
		d.UIDNext = imap.UID(mb.UIDNext)
	}
	if o.UIDValidity {
		d.UIDValidity = uint32(mb.UIDValidity)
	}
	if o.NumUnseen {
		n := uint32(mb.Unread)
		d.NumUnseen = &n
	}
	if o.Size {
		n := mb.Size
		d.Size = &n
	}
	if o.NumDeleted {
		n := uint32(0)
		d.NumDeleted = &n
	}
	return d
}

func (s *session) Status(n string, o *imap.StatusOptions) (*imap.StatusData, error) {
	mbs, err := s.b.store.ListMailboxes(ctx(), s.user.ID)
	if err != nil {
		return nil, s.b.err(err)
	}
	for _, mb := range mbs {
		if mb.Name == name(n) {
			return statusData(mb, o), nil
		}
	}
	return nil, errNoMailbox
}

func toFlags(f []imap.Flag) (bits store.Flag, keywords []string) {
	for _, fl := range f {
		switch strings.ToLower(string(fl)) {
		case `\seen`:
			bits |= store.FlagSeen
		case `\answered`:
			bits |= store.FlagAnswered
		case `\flagged`:
			bits |= store.FlagFlagged
		case `\deleted`:
			bits |= store.FlagDeleted
		case `\draft`:
			bits |= store.FlagDraft
		case `\recent`:
		default:
			if !strings.HasPrefix(string(fl), `\`) && len(fl) <= 64 {
				keywords = append(keywords, string(fl))
			}
		}
	}
	return bits, keywords
}

func fromFlags(bits store.Flag, keywords []string) []imap.Flag {
	var out []imap.Flag
	for i, f := range systemFlags {
		if bits&(1<<i) != 0 {
			out = append(out, f)
		}
	}
	for _, k := range keywords {
		out = append(out, imap.Flag(k))
	}
	return out
}

func (s *session) Append(n string, r imap.LiteralReader, o *imap.AppendOptions) (*imap.AppendData, error) {
	mb, err := s.mailbox(n)
	if err != nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	if s.b.cfg.MaxSize > 0 && r.Size() > s.b.cfg.MaxSize {
		return nil, errTooBig
	}
	bits, kws := toFlags(o.Flags)
	m, err := s.b.deliver.Append(ctx(), *s.user, mb.ID, bits, o.Time, r)
	if err != nil {
		return nil, s.b.err(err)
	}
	if len(kws) > 0 {
		s.b.store.SetKeywords(ctx(), s.user.ID, []int64{m.ID}, kws, nil)
	}
	return &imap.AppendData{UIDValidity: uint32(mb.UIDValidity), UID: imap.UID(m.UID)}, nil
}

// Poll reports changes to the selected mailbox since the last poll.
func (s *session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	// Drain notifications; the store is the source of truth.
	for {
		select {
		case <-s.events:
			continue
		default:
		}
		break
	}
	if s.sel == nil {
		return nil
	}
	return s.sync(w, allowExpunge)
}

func (s *session) sync(w *imapserver.UpdateWriter, allowExpunge bool) error {
	sel := s.sel
	changed, gone, highest, err := s.b.store.Changes(ctx(), s.user.ID, sel.mb.ID, sel.modseq)
	if errors.Is(err, store.ErrNotFound) {
		return w.WriteExpunge(1) // mailbox deleted under us; client will re-select
	}
	if err != nil {
		return s.b.err(err)
	}
	if highest == sel.modseq {
		return nil
	}
	if allowExpunge && len(gone) > 0 {
		goneSet := map[imap.UID]bool{}
		for _, u := range gone {
			goneSet[imap.UID(u)] = true
		}
		// Report from the highest sequence number down so numbers stay valid.
		for i := len(sel.uids) - 1; i >= 0; i-- {
			if goneSet[sel.uids[i]] {
				if err := w.WriteExpunge(uint32(i + 1)); err != nil {
					return err
				}
				delete(sel.ids, sel.uids[i])
				sel.uids = append(sel.uids[:i], sel.uids[i+1:]...)
			}
		}
	}
	var kw map[int64][]string
	added := false
	for _, m := range changed {
		uid := imap.UID(m.UID)
		if _, known := sel.ids[uid]; !known {
			if len(sel.uids) == 0 || uid > sel.uids[len(sel.uids)-1] {
				sel.uids = append(sel.uids, uid)
				sel.ids[uid] = m.ID
				added = true
			}
			continue
		}
		if kw == nil {
			kw, _ = s.b.store.KeywordsByMailbox(ctx(), sel.mb.ID)
		}
		if seq := sel.seq(uid); seq > 0 {
			if err := w.WriteMessageFlags(seq, uid, fromFlags(m.Flags, kw[m.ID])); err != nil {
				return err
			}
		}
	}
	if added {
		if err := w.WriteNumMessages(uint32(len(sel.uids))); err != nil {
			return err
		}
	}
	// Only advance past expunges once they have been reported.
	if allowExpunge || len(gone) == 0 {
		sel.modseq = highest
	}
	return nil
}

func (sel *selected) seq(uid imap.UID) uint32 {
	i := sort.Search(len(sel.uids), func(i int) bool { return sel.uids[i] >= uid })
	if i < len(sel.uids) && sel.uids[i] == uid {
		return uint32(i + 1)
	}
	return 0
}

func (s *session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	if s.sel != nil {
		if err := s.sync(w, true); err != nil {
			return err
		}
	}
	for {
		select {
		case <-stop:
			return nil
		case ev := <-s.events:
			if s.sel == nil {
				continue
			}
			for _, id := range ev.MailboxIDs {
				if id == s.sel.mb.ID {
					if err := s.sync(w, true); err != nil {
						return err
					}
					break
				}
			}
		case <-t.C:
			if s.sel != nil {
				if err := s.sync(w, true); err != nil {
					return err
				}
			}
		}
	}
}

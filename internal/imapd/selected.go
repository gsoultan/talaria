// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package imapd

import (
	"bufio"
	"bytes"
	"io"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/gsoultan/talaria/internal/store"
)

// static resolves "*" and $ in a number set against the current view.
func (sel *selected) static(numSet imap.NumSet) imap.NumSet {
	if imap.IsSearchRes(numSet) {
		return sel.searchRes
	}
	switch ns := numSet.(type) {
	case imap.SeqSet:
		out := make(imap.SeqSet, len(ns))
		copy(out, ns)
		max := uint32(len(sel.uids))
		for i := range out {
			staticRange(&out[i].Start, &out[i].Stop, max)
		}
		return out
	case imap.UIDSet:
		out := make(imap.UIDSet, len(ns))
		copy(out, ns)
		var max uint32
		if len(sel.uids) > 0 {
			max = uint32(sel.uids[len(sel.uids)-1])
		}
		for i := range out {
			staticRange((*uint32)(&out[i].Start), (*uint32)(&out[i].Stop), max)
		}
		return out
	}
	return numSet
}

func staticRange(start, stop *uint32, max uint32) {
	dyn := false
	if *start == 0 {
		*start, dyn = max, true
	}
	if *stop == 0 {
		*stop, dyn = max, true
	}
	if dyn && *start > *stop {
		*start, *stop = *stop, *start
	}
}

// pick returns (seq, uid) pairs in the view matching numSet.
func (sel *selected) pick(numSet imap.NumSet) (seqs []uint32, uids []imap.UID) {
	numSet = sel.static(numSet)
	for i, uid := range sel.uids {
		seq := uint32(i + 1)
		ok := false
		switch ns := numSet.(type) {
		case imap.SeqSet:
			ok = ns.Contains(seq)
		case imap.UIDSet:
			ok = ns.Contains(uid)
		}
		if ok {
			seqs = append(seqs, seq)
			uids = append(uids, uid)
		}
	}
	return seqs, uids
}

func (sel *selected) idsOf(uids []imap.UID) []int64 {
	out := make([]int64, 0, len(uids))
	for _, u := range uids {
		out = append(out, sel.ids[u])
	}
	return out
}

var errReadOnly = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "Mailbox is read-only"}

func (s *session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	sel := s.sel
	if sel.readOnly {
		return errReadOnly
	}
	msgs, err := s.b.store.MailboxMessages(ctx(), s.user.ID, sel.mb.ID)
	if err != nil {
		return s.b.err(err)
	}
	var ids []int64
	gone := map[imap.UID]bool{}
	for _, m := range msgs {
		uid := imap.UID(m.UID)
		if m.Flags&store.FlagDeleted == 0 || (uids != nil && !uids.Contains(uid)) {
			continue
		}
		if _, known := sel.ids[uid]; !known {
			continue
		}
		ids = append(ids, m.ID)
		gone[uid] = true
	}
	if len(ids) == 0 {
		return nil
	}
	mbs, err := s.b.store.ExpungeMessages(ctx(), s.user.ID, ids)
	if err != nil {
		return s.b.err(err)
	}
	for i := len(sel.uids) - 1; i >= 0; i-- {
		if gone[sel.uids[i]] {
			if err := w.WriteExpunge(uint32(i + 1)); err != nil {
				return err
			}
			delete(sel.ids, sel.uids[i])
			sel.uids = append(sel.uids[:i], sel.uids[i+1:]...)
		}
	}
	s.b.hub.Publish(s.user.ID, mbs...)
	return nil
}

func (s *session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, _ *imap.StoreOptions) error {
	sel := s.sel
	if sel.readOnly {
		return errReadOnly
	}
	_, uids := sel.pick(numSet)
	if len(uids) == 0 {
		return nil
	}
	ids := sel.idsOf(uids)
	bits, kws := toFlags(flags.Flags)
	var err error
	var mbs []int64
	switch flags.Op {
	case imap.StoreFlagsAdd:
		mbs, err = s.b.store.SetFlags(ctx(), s.user.ID, ids, bits, 0)
		if err == nil && len(kws) > 0 {
			err = s.b.store.SetKeywords(ctx(), s.user.ID, ids, kws, nil)
		}
	case imap.StoreFlagsDel:
		mbs, err = s.b.store.SetFlags(ctx(), s.user.ID, ids, 0, bits)
		if err == nil && len(kws) > 0 {
			err = s.b.store.SetKeywords(ctx(), s.user.ID, ids, nil, kws)
		}
	case imap.StoreFlagsSet:
		all := store.FlagSeen | store.FlagAnswered | store.FlagFlagged | store.FlagDeleted | store.FlagDraft
		mbs, err = s.b.store.SetFlags(ctx(), s.user.ID, ids, bits, all&^bits)
		if err == nil {
			err = s.b.store.ReplaceKeywords(ctx(), s.user.ID, ids, kws)
		}
	}
	if err != nil {
		return s.b.err(err)
	}
	s.b.hub.Publish(s.user.ID, mbs...)
	if !flags.Silent {
		return s.Fetch(w, uidSet(uids), &imap.FetchOptions{Flags: true})
	}
	return nil
}

func uidSet(uids []imap.UID) imap.UIDSet {
	var set imap.UIDSet
	set.AddNum(uids...)
	return set
}

func (s *session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	mb, err := s.mailbox(dest)
	if err != nil {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	_, uids := s.sel.pick(numSet)
	if len(uids) == 0 {
		return &imap.CopyData{UIDValidity: uint32(mb.UIDValidity)}, nil
	}
	created, err := s.b.store.CopyMessages(ctx(), s.user.TenantID, s.user.ID, s.sel.idsOf(uids), mb.ID)
	if err != nil {
		return nil, s.b.err(err)
	}
	data := &imap.CopyData{UIDValidity: uint32(mb.UIDValidity)}
	for i, m := range created {
		data.SourceUIDs.AddNum(uids[i])
		data.DestUIDs.AddNum(imap.UID(m.UID))
	}
	s.b.hub.Publish(s.user.ID, mb.ID)
	return data, nil
}

func (s *session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	sel := s.sel
	if sel.readOnly {
		return errReadOnly
	}
	mb, err := s.mailbox(dest)
	if err != nil {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	_, uids := sel.pick(numSet)
	if len(uids) == 0 {
		return nil
	}
	touched, moved, err := s.b.store.MoveMessagesUIDs(ctx(), s.user.ID, sel.idsOf(uids), mb.ID)
	if err != nil {
		return s.b.err(err)
	}
	data := &imap.CopyData{UIDValidity: uint32(mb.UIDValidity)}
	gone := map[imap.UID]bool{}
	for _, m := range moved {
		data.SourceUIDs.AddNum(imap.UID(m.OldUID))
		data.DestUIDs.AddNum(imap.UID(m.NewUID))
		gone[imap.UID(m.OldUID)] = true
	}
	if err := w.WriteCopyData(data); err != nil {
		return err
	}
	for i := len(sel.uids) - 1; i >= 0; i-- {
		if gone[sel.uids[i]] {
			if err := w.WriteExpunge(uint32(i + 1)); err != nil {
				return err
			}
			delete(sel.ids, sel.uids[i])
			sel.uids = append(sel.uids[:i], sel.uids[i+1:]...)
		}
	}
	s.b.hub.Publish(s.user.ID, touched...)
	return nil
}

func headerOnly(item *imap.FetchItemBodySection) bool {
	return len(item.Part) == 0 && item.Specifier == imap.PartSpecifierHeader
}

func (s *session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, o *imap.FetchOptions) error {
	sel := s.sel
	seqs, uids := sel.pick(numSet)
	if len(uids) == 0 {
		return nil
	}
	markSeen := false
	needFull := o.BodyStructure != nil || len(o.BinarySection) > 0 || len(o.BinarySectionSize) > 0
	needHeader := o.Envelope
	for _, bs := range o.BodySection {
		if !bs.Peek {
			markSeen = true
		}
		if headerOnly(bs) {
			needHeader = true
		} else {
			needFull = true
		}
	}
	if markSeen && !sel.readOnly {
		if mbs, err := s.b.store.SetFlags(ctx(), s.user.ID, sel.idsOf(uids), store.FlagSeen, 0); err == nil {
			s.b.hub.Publish(s.user.ID, mbs...)
		}
	}
	var kw map[int64][]string
	if o.Flags {
		kw, _ = s.b.store.KeywordsByMailbox(ctx(), sel.mb.ID)
	}
	for i, uid := range uids {
		m, err := s.b.store.MessageByUID(ctx(), s.user.ID, sel.mb.ID, int64(uid))
		if err != nil {
			continue // expunged meanwhile; the next poll reports it
		}
		rw := w.CreateMessage(seqs[i])
		rw.WriteUID(uid)
		if o.Flags {
			rw.WriteFlags(fromFlags(m.Flags, kw[m.ID]))
		}
		if o.InternalDate {
			rw.WriteInternalDate(time.Unix(m.InternalDate, 0))
		}
		if o.RFC822Size {
			rw.WriteRFC822Size(m.Size)
		}
		var raw []byte
		switch {
		case needFull:
			s.b.fetchSem <- struct{}{}
			raw, err = s.load(m, -1)
			<-s.b.fetchSem
		case needHeader:
			raw, err = s.load(m, 256<<10)
		}
		if err != nil {
			rw.Close()
			return s.b.err(err)
		}
		if o.Envelope {
			if h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw))); err == nil {
				rw.WriteEnvelope(imapserver.ExtractEnvelope(h))
			}
		}
		if o.BodyStructure != nil {
			rw.WriteBodyStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
		}
		for _, bs := range o.BodySection {
			buf := imapserver.ExtractBodySection(bytes.NewReader(raw), bs)
			wc := rw.WriteBodySection(bs, int64(len(buf)))
			if _, err := wc.Write(buf); err != nil {
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
		}
		for _, bs := range o.BinarySection {
			buf := imapserver.ExtractBinarySection(bytes.NewReader(raw), bs)
			wc := rw.WriteBinarySection(bs, int64(len(buf)))
			if _, err := wc.Write(buf); err != nil {
				return err
			}
			if err := wc.Close(); err != nil {
				return err
			}
		}
		for _, bss := range o.BinarySectionSize {
			rw.WriteBinarySectionSize(bss, imapserver.ExtractBinarySectionSize(bytes.NewReader(raw), bss))
		}
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
}

// load reads a message body. With limit >= 0 it reads only the header (up
// to limit bytes), which is all ENVELOPE and BODY[HEADER...] need.
func (s *session) load(m store.Message, limit int) ([]byte, error) {
	full, err := s.b.store.Message(ctx(), s.user.ID, m.ID)
	if err != nil {
		return nil, err
	}
	r, err := s.b.blobs.Open(s.user.TenantID, full.BlobHash)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if limit < 0 {
		return io.ReadAll(r)
	}
	br := bufio.NewReader(io.LimitReader(r, int64(limit)))
	var buf bytes.Buffer
	for {
		line, err := br.ReadSlice('\n')
		buf.Write(line)
		if err != nil || len(bytes.TrimRight(line, "\r\n")) == 0 {
			break
		}
	}
	return buf.Bytes(), nil
}

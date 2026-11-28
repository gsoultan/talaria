// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package imapd

import (
	"bufio"
	"bytes"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// matcher evaluates search criteria against the selected mailbox. Metadata
// comes from the database; TEXT and BODY use the full-text index; other
// header keys read the stored header, once per message.
type matcher struct {
	s        *session
	keywords map[int64][]string
	fts      map[string]map[int64]bool
	headers  map[int64]textproto.Header
	err      error
}

func (s *session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	sel := s.sel
	msgs, err := s.b.store.MailboxMessages(ctx(), s.user.ID, sel.mb.ID)
	if err != nil {
		return nil, s.b.err(err)
	}
	byUID := make(map[imap.UID]store.Message, len(msgs))
	for _, m := range msgs {
		byUID[imap.UID(m.UID)] = m
	}
	mt := &matcher{s: s, fts: map[string]map[int64]bool{}, headers: map[int64]textproto.Header{}}
	if usesKeywords(criteria) {
		mt.keywords, _ = s.b.store.KeywordsByMailbox(ctx(), sel.mb.ID)
	}
	data := &imap.SearchData{}
	var seqs imap.SeqSet
	var uids imap.UIDSet
	for i, uid := range sel.uids {
		m, ok := byUID[uid]
		if !ok {
			continue // expunged since the last sync
		}
		seq := uint32(i + 1)
		if !mt.match(sel, seq, uid, m, criteria) {
			if mt.err != nil {
				return nil, s.b.err(mt.err)
			}
			continue
		}
		num := seq
		if kind == imapserver.NumKindUID {
			num = uint32(uid)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
		seqs.AddNum(seq)
		uids.AddNum(uid)
	}
	if kind == imapserver.NumKindUID {
		data.All = uids
	} else {
		data.All = seqs
	}
	if options != nil && options.ReturnSave {
		sel.searchRes = uids
	}
	return data, nil
}

func usesKeywords(c *imap.SearchCriteria) bool {
	if _, kws := toFlags(append(append([]imap.Flag{}, c.Flag...), c.NotFlag...)); len(kws) > 0 {
		return true
	}
	for i := range c.Not {
		if usesKeywords(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if usesKeywords(&c.Or[i][0]) || usesKeywords(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

func day(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC) }

func unixDay(sec int64) time.Time { return day(time.Unix(sec, 0).UTC()) }

func (mt *matcher) match(sel *selected, seq uint32, uid imap.UID, m store.Message, c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if !inSet(sel, set, seq, uid) {
			return false
		}
	}
	for _, set := range c.UID {
		if !inSet(sel, set, seq, uid) {
			return false
		}
	}
	if !c.Since.IsZero() && unixDay(m.InternalDate).Before(day(c.Since)) {
		return false
	}
	if !c.Before.IsZero() && !unixDay(m.InternalDate).Before(day(c.Before)) {
		return false
	}
	sent := m.SentDate
	if sent == 0 {
		sent = m.InternalDate
	}
	if !c.SentSince.IsZero() && unixDay(sent).Before(day(c.SentSince)) {
		return false
	}
	if !c.SentBefore.IsZero() && !unixDay(sent).Before(day(c.SentBefore)) {
		return false
	}
	if c.Larger > 0 && m.Size <= c.Larger {
		return false
	}
	if c.Smaller > 0 && m.Size >= c.Smaller {
		return false
	}
	for _, f := range c.Flag {
		if !mt.hasFlag(m, f) {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if mt.hasFlag(m, f) {
			return false
		}
	}
	if c.ModSeq != nil && uint64(m.ModSeq) < c.ModSeq.ModSeq {
		return false
	}
	for _, h := range c.Header {
		if !mt.header(m, h.Key, h.Value) {
			return false
		}
	}
	for _, t := range c.Text {
		if !mt.text(m, t) {
			return false
		}
	}
	for _, t := range c.Body {
		if !mt.text(m, t) {
			return false
		}
	}
	for i := range c.Not {
		if mt.match(sel, seq, uid, m, &c.Not[i]) {
			return false
		}
	}
	for i := range c.Or {
		if !mt.match(sel, seq, uid, m, &c.Or[i][0]) && !mt.match(sel, seq, uid, m, &c.Or[i][1]) {
			return false
		}
	}
	return mt.err == nil
}

func (mt *matcher) hasFlag(m store.Message, f imap.Flag) bool {
	bits, kws := toFlags([]imap.Flag{f})
	if bits != 0 {
		return m.Flags&bits != 0
	}
	if len(kws) == 0 {
		return false // \Recent and unknown system flags
	}
	for _, k := range mt.keywords[m.ID] {
		if strings.EqualFold(k, string(f)) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func (mt *matcher) header(m store.Message, key, value string) bool {
	switch strings.ToLower(key) {
	case "subject":
		return contains(m.Subject, value)
	case "from":
		return contains(m.FromName+" "+m.FromAddr, value)
	case "to":
		return contains(m.To, value)
	case "cc":
		return contains(m.Cc, value)
	case "message-id":
		return contains(m.MessageID, value)
	}
	h, ok := mt.headers[m.ID]
	if !ok {
		raw, err := mt.s.load(m, 256<<10)
		if err != nil {
			mt.err = err
			return false
		}
		h, _ = textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
		mt.headers[m.ID] = h
	}
	vals := h.Values(key)
	if value == "" {
		return len(vals) > 0
	}
	for _, v := range vals {
		if contains(mail.DecodeHeader(v), value) {
			return true
		}
	}
	return false
}

// text matches TEXT and BODY keys through the full-text index. The index
// matches whole-word prefixes rather than arbitrary substrings, which is
// what people mean when they search mail; subject and addresses are also
// checked as plain substrings.
func (mt *matcher) text(m store.Message, t string) bool {
	if contains(m.Subject, t) || contains(m.FromAddr, t) || contains(m.FromName, t) {
		return true
	}
	set, ok := mt.fts[t]
	if !ok {
		var err error
		set, err = mt.s.b.store.MatchIDs(ctx(), mt.s.user.ID, mt.s.sel.mb.ID, t)
		if err != nil {
			mt.err = err
			return false
		}
		mt.fts[t] = set
	}
	return set[m.ID]
}

func inSet(sel *selected, set imap.NumSet, seq uint32, uid imap.UID) bool {
	switch ns := sel.static(set).(type) {
	case imap.SeqSet:
		return ns.Contains(seq)
	case imap.UIDSet:
		return ns.Contains(uid)
	}
	return false
}

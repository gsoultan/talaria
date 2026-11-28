// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package mail parses messages, checks sender authentication and delivers
// messages into mailboxes.
package mail

import (
	"bufio"
	"html"
	"io"
	"mime"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // decode legacy charsets
	gomail "github.com/emersion/go-message/mail"
)

// Summary is what the list view and search need from a message, extracted
// once at delivery so the body is never parsed again for listing.
type Summary struct {
	Subject        string
	FromName       string
	FromAddr       string
	To             string
	Cc             string
	MessageID      string
	InReplyTo      string
	References     []string
	SentDate       int64
	Preview        string
	HasAttachments bool
	// Text is the plain text for the search index, capped at maxText bytes.
	Text string
}

const (
	maxText    = 64 << 10
	previewLen = 180
	maxParts   = 100
)

// Summarize reads a message and extracts its summary. Malformed messages
// still produce a best-effort summary.
func Summarize(r io.Reader) Summary {
	var s Summary
	e, err := message.Read(bufio.NewReaderSize(r, 32<<10))
	if e == nil {
		return s
	}
	_ = err // unknown charset/encoding: keep going with what we have
	h := gomail.Header{Header: e.Header}
	s.Subject, _ = h.Subject()
	s.Subject = clean(s.Subject, 998)
	if from, err := h.AddressList("From"); err == nil && len(from) > 0 {
		s.FromName, s.FromAddr = clean(from[0].Name, 200), strings.ToLower(from[0].Address)
	} else {
		s.FromAddr = clean(e.Header.Get("From"), 200)
	}
	s.To = addrList(h, "To")
	s.Cc = addrList(h, "Cc")
	s.MessageID, _ = h.MessageID()
	if ids, _ := h.MsgIDList("In-Reply-To"); len(ids) > 0 {
		s.InReplyTo = ids[0]
	}
	if refs, _ := h.MsgIDList("References"); len(refs) > 0 {
		if len(refs) > 20 {
			refs = refs[len(refs)-20:]
		}
		s.References = refs
	}
	if d, err := h.Date(); err == nil && !d.IsZero() {
		s.SentDate = d.Unix()
	}

	var plain, htmlText strings.Builder
	parts := 0
	e.Walk(func(path []int, part *message.Entity, err error) error {
		parts++
		if err != nil || parts > maxParts {
			return nil
		}
		ct, params, _ := part.Header.ContentType()
		disp, dparams, _ := part.Header.ContentDisposition()
		if disp == "attachment" || dparams["filename"] != "" || (params["name"] != "" && !strings.HasPrefix(ct, "text/")) {
			s.HasAttachments = true
			return nil
		}
		switch ct {
		case "text/plain":
			if plain.Len() < maxText {
				readText(&plain, part.Body)
			}
		case "text/html":
			if htmlText.Len() < maxText {
				readText(&htmlText, part.Body)
			}
		}
		return nil
	})
	text := plain.String()
	if strings.TrimSpace(text) == "" {
		text = HTMLToText(htmlText.String())
	}
	s.Text = truncate(text, maxText)
	s.Preview = preview(text)
	return s
}

func readText(b *strings.Builder, r io.Reader) {
	buf, _ := io.ReadAll(io.LimitReader(r, int64(maxText-b.Len())))
	if !utf8.Valid(buf) {
		buf = []byte(strings.ToValidUTF8(string(buf), "�"))
	}
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	b.Write(buf)
}

func addrList(h gomail.Header, key string) string {
	list, err := h.AddressList(key)
	if err != nil {
		return clean(h.Get(key), 1000)
	}
	var out []string
	for _, a := range list {
		if len(out) == 50 {
			break
		}
		if a.Name != "" {
			out = append(out, clean(a.Name, 100)+" <"+a.Address+">")
		} else {
			out = append(out, a.Address)
		}
	}
	return strings.Join(out, ", ")
}

var (
	reDrop  = regexp.MustCompile(`(?is)<(script|style|head|title)[^>]*>.*?</(script|style|head|title)>`)
	reBlock = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/li|/h[1-6]|p|div|tr|li)\b[^>]*>`)
	reTag   = regexp.MustCompile(`<[^>]*>`)
	reSpace = regexp.MustCompile(`[ \t\r\f\v]+`)
	reLines = regexp.MustCompile(`\n\s*\n+`)
)

// HTMLToText is a fast, lossy HTML to text conversion for previews and search.
func HTMLToText(s string) string {
	if s == "" {
		return ""
	}
	s = reDrop.ReplaceAllString(s, " ")
	s = reBlock.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = reSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(reLines.ReplaceAllString(s, "\n\n"))
}

// preview skips quoted lines and signatures and collapses whitespace.
func preview(text string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "--" || strings.HasPrefix(t, "-- ") {
			break
		}
		if t == "" || strings.HasPrefix(t, ">") {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t)
		if b.Len() > previewLen*2 {
			break
		}
	}
	return clean(b.String(), previewLen)
}

// clean collapses whitespace, drops control characters and truncates.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	return truncate(s, n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := n
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}

// DecodeHeader decodes RFC 2047 words, ignoring errors.
func DecodeHeader(s string) string {
	d := mime.WordDecoder{CharsetReader: message.CharsetReader}
	out, err := d.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

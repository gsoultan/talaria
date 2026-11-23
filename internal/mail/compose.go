// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
)

// Compose is a message written in the webmail.
type Compose struct {
	From        *gomail.Address
	To, Cc, Bcc []*gomail.Address
	Subject     string
	Text        string
	HTML        string
	InReplyTo   string
	References  []string
	MessageID   string
	Attachments []NewAttachment
	// KeepBcc writes the Bcc header (drafts and the Sent copy).
	KeepBcc bool
}

// NewAttachment is a file attached in the composer.
type NewAttachment struct {
	Filename    string
	ContentType string
	ContentID   string
	Data        []byte
}

// ParseAddresses parses "Name <a@b>" or bare addresses.
func ParseAddresses(list []string) ([]*gomail.Address, error) {
	var out []*gomail.Address
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		as, err := gomail.ParseAddressList(s)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", s)
		}
		out = append(out, as...)
	}
	return out, nil
}

// Write renders c as RFC 5322 with MIME parts:
// multipart/mixed(multipart/alternative(text, html), attachments...).
func (c *Compose) Write(w io.Writer) error {
	if c.From == nil {
		return errors.New("from is required")
	}
	var h gomail.Header
	h.SetDate(time.Now())
	h.SetAddressList("From", []*gomail.Address{c.From})
	if len(c.To) > 0 {
		h.SetAddressList("To", c.To)
	}
	if len(c.Cc) > 0 {
		h.SetAddressList("Cc", c.Cc)
	}
	if c.KeepBcc && len(c.Bcc) > 0 {
		h.SetAddressList("Bcc", c.Bcc)
	}
	h.SetSubject(c.Subject)
	h.SetMessageID(c.MessageID)
	if c.InReplyTo != "" {
		h.SetMsgIDList("In-Reply-To", []string{strings.Trim(c.InReplyTo, "<>")})
	}
	if len(c.References) > 0 {
		refs := make([]string, len(c.References))
		for i, r := range c.References {
			refs[i] = strings.Trim(r, "<>")
		}
		h.SetMsgIDList("References", refs)
	}
	text := c.Text
	if text == "" && c.HTML != "" {
		text = HTMLToText(c.HTML)
	}

	mw, err := gomail.CreateWriter(w, h)
	if err != nil {
		return err
	}
	iw, err := mw.CreateInline()
	if err != nil {
		return err
	}
	if err := writePart(iw, "text/plain", text); err != nil {
		return err
	}
	if c.HTML != "" {
		if err := writePart(iw, "text/html", c.HTML); err != nil {
			return err
		}
	}
	if err := iw.Close(); err != nil {
		return err
	}
	for _, a := range c.Attachments {
		var ah gomail.AttachmentHeader
		ct := a.ContentType
		if ct == "" || strings.ContainsAny(ct, "\r\n") {
			ct = "application/octet-stream"
		}
		ah.Set("Content-Type", ct)
		ah.SetFilename(clean(a.Filename, 255))
		if a.ContentID != "" {
			ah.Set("Content-Id", "<"+clean(strings.Trim(a.ContentID, "<>"), 200)+">")
			ah.Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": clean(a.Filename, 255)}))
		}
		aw, err := mw.CreateAttachment(ah)
		if err != nil {
			return err
		}
		if _, err := aw.Write(a.Data); err != nil {
			return err
		}
		if err := aw.Close(); err != nil {
			return err
		}
	}
	return mw.Close()
}

func writePart(iw *gomail.InlineWriter, ct, body string) error {
	var ph gomail.InlineHeader
	ph.Set("Content-Type", ct+"; charset=utf-8")
	ph.Set("Content-Transfer-Encoding", "quoted-printable")
	pw, err := iw.CreatePart(ph)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(pw, body); err != nil {
		return err
	}
	return pw.Close()
}

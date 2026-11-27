// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"fmt"
	"html"
	"mime"
	"strings"
	"time"

	"github.com/gsoultan/talaria/internal/store"
)

// SendDigests tells each user what was held for them since their last
// digest, with a link to review it in the webmail. It returns how many
// digests went out.
func (d *Deliverer) SendDigests(ctx context.Context, webURL string) (int, error) {
	sent := 0
	for ctx.Err() == nil {
		due, err := d.Store.DigestDue(ctx, 1000)
		if err != nil || len(due) == 0 {
			return sent, err
		}
		for len(due) > 0 {
			n := 1
			for n < len(due) && due[n].UserID == due[0].UserID {
				n++
			}
			batch := due[:n]
			due = due[n:]
			if err := d.sendDigest(ctx, webURL, batch); err != nil {
				return sent, err
			}
			ids := make([]int64, len(batch))
			for i, h := range batch {
				ids[i] = h.ID
			}
			if err := d.Store.MarkNotified(ctx, ids); err != nil {
				return sent, err
			}
			sent++
		}
	}
	return sent, ctx.Err()
}

func (d *Deliverer) sendDigest(ctx context.Context, webURL string, held []store.Held) error {
	u, err := d.Store.User(ctx, held[0].UserID)
	if err != nil {
		return err
	}
	link := strings.TrimSuffix(webURL, "/") + "/quarantine"
	var text, body strings.Builder
	noun := "messages were"
	if len(held) == 1 {
		noun = "message was"
	}
	fmt.Fprintf(&text, "%d %s held for you because they look like spam or carry dangerous attachments.\r\n\r\n", len(held), noun)
	fmt.Fprintf(&body, `<p>%d %s held for you because they look like spam or carry dangerous attachments.</p><table cellpadding="6" style="border-collapse:collapse">`, len(held), noun)
	body.WriteString(`<tr style="text-align:left"><th>From</th><th>Subject</th><th>Reason</th><th>Received</th></tr>`)
	for _, h := range held {
		from := h.FromAddr
		if h.FromName != "" {
			from = h.FromName + " <" + h.FromAddr + ">"
		}
		reason := "Likely spam"
		if h.Reason == store.HeldMalware {
			reason = "Dangerous attachment"
		}
		when := time.Unix(h.CreatedAt, 0).UTC().Format("2 Jan 15:04 UTC")
		fmt.Fprintf(&text, "- %s\r\n  %s\r\n  %s, %s\r\n", from, h.Subject, reason, when)
		fmt.Fprintf(&body, `<tr style="border-top:1px solid #ddd"><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(from), html.EscapeString(h.Subject), reason, when)
	}
	fmt.Fprintf(&text, "\r\nReview, release or delete them at %s\r\nHeld mail is deleted after a while.\r\n", link)
	fmt.Fprintf(&body, `</table><p><a href="%s">Review held mail</a></p><p style="color:#666">Held mail is deleted after a while.</p>`, html.EscapeString(link))

	from := "postmaster@" + d.Hostname
	boundary := fmt.Sprintf("q%x", time.Now().UnixNano())
	var msg strings.Builder
	fmt.Fprintf(&msg, "From: %s <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <digest-%d-%d@%s>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\n",
		mime.QEncoding.Encode("utf-8", "Mail quarantine"), from, u.Address(),
		mime.QEncoding.Encode("utf-8", fmt.Sprintf("%d held %s", len(held), map[bool]string{true: "message", false: "messages"}[len(held) == 1])),
		time.Now().Format(time.RFC1123Z), u.ID, held[len(held)-1].ID, d.Hostname)
	fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%s\r\n\r\n", boundary)
	fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n", boundary, text.String())
	fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n<!doctype html><html><body style=\"font-family:sans-serif\">%s</body></html>\r\n--%s--\r\n", boundary, body.String(), boundary)
	_, err = d.Deliver(ctx, Inbound{Env: Envelope{MailFrom: from, Helo: d.Hostname}, Rcpts: []store.User{u}, Proto: "LOCAL", Trusted: true}, strings.NewReader(msg.String()))
	return err
}

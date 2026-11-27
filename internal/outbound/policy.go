// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"context"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"

	"github.com/gsoultan/talaria/internal/dlp"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// PolicyError is a message a data loss prevention policy stopped.
type PolicyError struct {
	Action  string // dlp.Block or dlp.Warn
	Matches []dlp.Match
}

func (e *PolicyError) Error() string {
	var names []string
	for _, m := range e.Matches {
		if m.Policy.Action == e.Action {
			names = append(names, fmt.Sprintf("%s (%d found)", m.Policy.Name, m.Count))
		}
	}
	if e.Action == dlp.Warn {
		return "this message may contain sensitive data: " + strings.Join(names, ", ")
	}
	return "blocked by policy: " + strings.Join(names, ", ")
}

// policyResult is what the policies decided for a message that may go.
type policyResult struct {
	requireTLS bool
	notify     []dlp.Match
	subject    string
	rcpts      []string
}

// checkPolicies runs the tenant's policies. It returns a PolicyError to
// stop the message.
func (s *Submitter) checkPolicies(ctx context.Context, sub Submission, h gomail.Header, rewind func() io.Reader) (policyResult, error) {
	var res policyResult
	all, err := s.Store.DLPPolicies(ctx, sub.User.TenantID, true)
	if err != nil || len(all) == 0 {
		return res, err
	}
	external := false
	for _, rc := range sub.Rcpts {
		if _, dom, err := store.SplitAddress(rc); err == nil && !s.Store.IsLocalDomain(ctx, dom) {
			external = true
		}
	}
	var policies []dlp.Policy
	for _, p := range all {
		if p.ExternalOnly && !external {
			continue
		}
		policies = append(policies, dlp.Policy{ID: p.ID, Name: p.Name, Detector: p.Detector, Pattern: p.Pattern, MinCount: p.MinCount,
			Action: p.Action, ExternalOnly: p.ExternalOnly, Notify: p.Notify})
	}
	if len(policies) == 0 {
		return res, nil
	}
	matches := dlp.Evaluate(dlp.Text(rewind()), policies)
	if len(matches) == 0 {
		return res, nil
	}
	res.subject, _ = h.Subject()
	res.rcpts = sub.Rcpts
	top := matches[0].Policy.Action
	decided := top
	if top == dlp.Warn && (sub.Confirmed || !sub.CanConfirm) {
		decided = "warned" // sent after a warning, or by an app that cannot ask
	}
	if s.PolicyHit != nil {
		s.PolicyHit(ctx, sub, res.subject, sub.Rcpts, matches, decided)
	}
	s.log().Info("policy match", "user", sub.User.Address(), "policy", matches[0].Policy.Name, "action", decided)
	switch decided {
	case dlp.Block:
		return res, &PolicyError{Action: dlp.Block, Matches: matches}
	case dlp.Warn:
		return res, &PolicyError{Action: dlp.Warn, Matches: matches}
	}
	for _, m := range matches {
		switch m.Policy.Action {
		case dlp.Encrypt:
			res.requireTLS = true
		case dlp.Notify, dlp.Warn: // a warn here was confirmed, so tell the contact
			res.notify = append(res.notify, m)
		}
	}
	return res, nil
}

// notifyPolicies tells each notify policy's contact (or the tenant's
// admins) that a message matched. The notice names the policy and shows
// masked samples, never the message itself.
func (s *Submitter) notifyPolicies(ctx context.Context, sub Submission, r policyResult) {
	for _, m := range r.notify {
		var to []store.User
		if m.Policy.Notify != "" {
			if u, err := s.Store.ResolveRecipient(ctx, m.Policy.Notify); err == nil && u.TenantID == sub.User.TenantID {
				to = append(to, u)
			}
		}
		if len(to) == 0 {
			to, _ = s.Store.TenantAdmins(ctx, sub.User.TenantID)
		}
		if len(to) == 0 {
			continue
		}
		var b strings.Builder
		from := "postmaster@" + s.Hostname
		fmt.Fprintf(&b, "From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
			mime.QEncoding.Encode("utf-8", "Data loss prevention"), from, "<"+to[0].Address()+">",
			mime.QEncoding.Encode("utf-8", "Policy matched: "+m.Policy.Name), time.Now().Format(time.RFC1123Z), newMessageID(s.Hostname))
		fmt.Fprintf(&b, "A message matched the policy %q and was sent.%s\r\n\r\nFrom:    %s\r\nTo:      %s\r\nSubject: %s\r\nFound:   %d (%s)\r\n",
			m.Policy.Name, confirmedNote(m), sub.User.Address(), strings.Join(r.rcpts, ", "), r.subject, m.Count, strings.Join(m.Samples, ", "))
		if _, err := s.Deliver.Deliver(ctx, mail.Inbound{Env: mail.Envelope{MailFrom: from, Helo: s.Hostname}, Rcpts: to, Trusted: true}, strings.NewReader(b.String())); err != nil {
			s.log().Warn("policy notice", "err", err)
		}
	}
}

func confirmedNote(m dlp.Match) string {
	if m.Policy.Action == dlp.Warn {
		return " The sender was warned and sent it anyway, or used a mail app that cannot ask."
	}
	return ""
}

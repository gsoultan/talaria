// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// QuarantinePolicy is who may release what.
type QuarantinePolicy struct {
	// UserReleaseMalware lets people release held malware themselves.
	UserReleaseMalware bool
	KeepDays           int
}

func heldOf(h store.Held, canRelease bool) domain.HeldMessage {
	return domain.HeldMessage{ID: h.ID, TenantID: h.TenantID, Recipient: h.Recipient, Reason: domain.HeldReason(h.Reason), Detail: h.Detail,
		SpamScore: h.SpamScore, EnvFrom: h.EnvFrom, FromName: h.FromName, FromAddr: h.FromAddr, Subject: h.Subject, Size: h.Size,
		CreatedAt: h.CreatedAt, CanRelease: canRelease}
}

func (p QuarantinePolicy) userMay(h store.Held) bool {
	return h.Reason != store.HeldMalware || p.UserReleaseMalware
}

// ListQuarantine returns the signed-in user's held mail.
func (s *Mail) ListQuarantine(ctx context.Context, in domain.ListQuarantine) (domain.HeldMessages, error) {
	u := userOf(ctx)
	hs, err := s.Store.ListHeld(ctx, store.HeldFilter{UserID: u.ID, Query: in.Query, Before: in.Before})
	if err != nil {
		return domain.HeldMessages{}, storeErr(err)
	}
	out := domain.HeldMessages{Messages: make([]domain.HeldMessage, len(hs)), KeepDays: s.Quarantine.KeepDays}
	for i, h := range hs {
		out.Messages[i] = heldOf(h, s.Quarantine.userMay(h))
	}
	return out, nil
}

// own loads a held message of the signed-in user.
func (s *Mail) own(ctx context.Context, id int64) (store.Held, error) {
	h, err := s.Store.HeldMessage(ctx, id)
	if err != nil {
		return h, storeErr(err)
	}
	if h.UserID != userOf(ctx).ID {
		return h, storeErr(store.ErrNotFound)
	}
	return h, nil
}

// ReleaseQuarantined delivers a held message to the user's Inbox.
func (s *Mail) ReleaseQuarantined(ctx context.Context, in domain.ReleaseQuarantined) (domain.Done, error) {
	h, err := s.own(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	if !s.Quarantine.userMay(h) {
		return domain.Done{}, forbidden("an admin must review mail held for dangerous attachments")
	}
	if _, err := s.Deliver.Release(ctx, h); err != nil {
		return domain.Done{}, storeErr(err)
	}
	return domain.Done{}, nil
}

// DeleteQuarantined deletes a held message.
func (s *Mail) DeleteQuarantined(ctx context.Context, in domain.DeleteQuarantined) (domain.Done, error) {
	h, err := s.own(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.DeleteHeld(ctx, h.ID))
}

// ListHeldMail returns a tenant's held mail.
func (s *Admin) ListHeldMail(ctx context.Context, in domain.ListHeldMail) (domain.HeldMessages, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.HeldMessages{}, err
	}
	hs, err := s.Store.ListHeld(ctx, store.HeldFilter{TenantID: tid, Query: in.Query, Reason: string(in.Reason), Before: in.Before})
	if err != nil {
		return domain.HeldMessages{}, storeErr(err)
	}
	out := domain.HeldMessages{Messages: make([]domain.HeldMessage, len(hs)), KeepDays: s.Quarantine.KeepDays}
	for i, h := range hs {
		out.Messages[i] = heldOf(h, true)
	}
	return out, nil
}

// held loads a held message the caller may manage.
func (s *Admin) held(ctx context.Context, id int64) (store.Held, error) {
	h, err := s.Store.HeldMessage(ctx, id)
	if err != nil {
		return h, storeErr(err)
	}
	if _, _, err := scope(ctx, h.TenantID); err != nil {
		return h, err
	}
	return h, nil
}

// GetHeldMail returns a held message's headers and text for review.
func (s *Admin) GetHeldMail(ctx context.Context, in domain.GetHeldMail) (domain.HeldMailDetail, error) {
	h, err := s.held(ctx, in.ID)
	if err != nil {
		return domain.HeldMailDetail{}, err
	}
	r, err := s.Blobs.Open(h.TenantID, h.BlobHash)
	if err != nil {
		return domain.HeldMailDetail{}, internal(err)
	}
	d, _ := mail.ReadDetail(r)
	r.Close()
	text := d.Text
	if text == "" && d.HTML != "" {
		text = mail.HTMLToText(d.HTML)
	}
	out := domain.HeldMailDetail{Message: heldOf(h, true), TextBody: text,
		Headers: make([]domain.Header, 0, len(d.Headers)), Attachments: make([]domain.Attachment, 0, len(d.Parts))}
	for _, hd := range d.Headers {
		out.Headers = append(out.Headers, domain.Header{Name: hd[0], Value: hd[1]})
	}
	for _, p := range d.Parts {
		out.Attachments = append(out.Attachments, domain.Attachment{Part: p.Path, Filename: p.Filename, ContentType: p.ContentType, Size: p.Size})
	}
	return out, nil
}

// ReleaseHeldMail delivers a held message to its recipient.
func (s *Admin) ReleaseHeldMail(ctx context.Context, in domain.ReleaseHeldMail) (domain.Done, error) {
	h, err := s.held(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	if _, err := s.Deliver.Release(ctx, h); err != nil {
		return domain.Done{}, storeErr(err)
	}
	return domain.Done{}, nil
}

// DeleteHeldMail deletes a held message.
func (s *Admin) DeleteHeldMail(ctx context.Context, in domain.DeleteHeldMail) (domain.Done, error) {
	h, err := s.held(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.DeleteHeld(ctx, h.ID))
}

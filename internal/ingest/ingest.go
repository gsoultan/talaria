// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package ingest accepts raw inbound messages over HTTPS, for servers that
// cannot receive on port 25 (Cloudflare Email Routing with an Email Worker,
// or an external MX that forwards through the tunnel).
package ingest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Path is where the handler is mounted.
const Path = "POST /ingest/v1/message"

// Handler delivers one message per request.
//
//	Authorization: Bearer <token>
//	X-Envelope-From: sender@example.com
//	X-Envelope-To: one@your.domain, two@your.domain
//	body: the raw RFC 5322 message
//
// Responses: 200 delivered; 400 bad request; 401 bad token; 413 too large;
// 550 refused for good (do not retry); 503 temporary (retry later).
type Handler struct {
	Token   string
	Store   *store.Store
	Deliver *mail.Deliverer
	Log     *slog.Logger
}

type result struct {
	Delivered []string          `json:"delivered"`
	Rejected  map[string]string `json:"rejected,omitempty"`
	Error     string            `json:"error,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	want := sha256.Sum256([]byte(h.Token))
	got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if h.Token == "" || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var res result
	var users []store.User
	var addrs []string
	for _, v := range r.Header.Values("X-Envelope-To") {
		for a := range strings.SplitSeq(v, ",") {
			if a = strings.TrimSpace(a); a != "" && len(addrs) < 100 {
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		writeJSON(w, http.StatusBadRequest, result{Error: "X-Envelope-To is required"})
		return
	}
	for _, a := range addrs {
		u, err := h.Store.ResolveRecipient(r.Context(), a)
		switch {
		case err == nil && !u.Suspended:
			users = append(users, u)
			res.Delivered = append(res.Delivered, a)
		case err == nil:
			res.reject(a, "mailbox disabled")
		case errors.Is(err, store.ErrNotFound):
			res.reject(a, "no such user")
		default:
			h.Log.Error("ingest resolve", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, result{Error: "temporary failure"})
			return
		}
	}
	if len(users) == 0 {
		writeJSON(w, 550, res)
		return
	}
	if h.Deliver.MaxSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.Deliver.MaxSize+1)
	}
	_, err := h.Deliver.Deliver(r.Context(), mail.Inbound{
		Env:   mail.Envelope{MailFrom: r.Header.Get("X-Envelope-From"), Helo: "ingest"},
		Rcpts: users, Proto: "HTTPS",
	}, r.Body)
	var rej *mail.RejectError
	var tooBig *http.MaxBytesError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, mail.ErrTooLarge), errors.As(err, &tooBig):
		writeJSON(w, http.StatusRequestEntityTooLarge, result{Error: "message too large"})
	case errors.As(err, &rej):
		writeJSON(w, 550, result{Error: rej.Reason})
	case errors.Is(err, store.ErrQuotaExceeded):
		writeJSON(w, 550, result{Error: "mailbox full"})
	default:
		h.Log.Error("ingest deliver", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, result{Error: "temporary failure"})
	}
}

func (r *result) reject(addr, why string) {
	if r.Rejected == nil {
		r.Rejected = map[string]string{}
	}
	r.Rejected[addr] = why
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

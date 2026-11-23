// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package hub fans out mailbox change notifications to live sessions
// (webmail streams, IMAP IDLE). Events only say which mailboxes changed;
// listeners fetch the changes by modseq, so a dropped event costs nothing
// but a little latency.
package hub

import "sync"

// Event says that mailboxes of a user changed.
type Event struct {
	UserID     int64
	MailboxIDs []int64
}

// Hub is an in-process pub/sub keyed by user.
type Hub struct {
	mu   sync.Mutex
	subs map[int64]map[chan Event]struct{}
}

// New returns an empty hub.
func New() *Hub { return &Hub{subs: map[int64]map[chan Event]struct{}{}} }

// Subscribe returns a channel of events for userID and a cancel function.
func (h *Hub) Subscribe(userID int64) (<-chan Event, func()) {
	ch := make(chan Event, 16)
	h.mu.Lock()
	if h.subs[userID] == nil {
		h.subs[userID] = map[chan Event]struct{}{}
	}
	h.subs[userID][ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs[userID], ch)
			if len(h.subs[userID]) == 0 {
				delete(h.subs, userID)
			}
			h.mu.Unlock()
		})
	}
}

// Publish notifies every subscriber of userID without blocking. A slow
// subscriber whose buffer is full misses the event; it catches up on the
// next one because listeners always re-read by modseq.
func (h *Hub) Publish(userID int64, mailboxIDs ...int64) {
	if len(mailboxIDs) == 0 {
		return
	}
	ev := Event{UserID: userID, MailboxIDs: mailboxIDs}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[userID] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribers returns the number of live subscriptions (for metrics).
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.subs {
		n += len(s)
	}
	return n
}

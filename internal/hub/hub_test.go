// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package hub

import "testing"

func TestHub(t *testing.T) {
	h := New()
	a, cancel := h.Subscribe(1)
	b, cancelB := h.Subscribe(2)
	defer cancelB()
	h.Publish(1, 10)
	if ev := <-a; ev.MailboxIDs[0] != 10 {
		t.Fatal(ev)
	}
	select {
	case <-b:
		t.Fatal("wrong user got event")
	default:
	}
	for range 100 {
		h.Publish(1, 1) // must not block when full
	}
	cancel()
	cancel()
	if h.Subscribers() != 1 {
		t.Fatal("cancel")
	}
}

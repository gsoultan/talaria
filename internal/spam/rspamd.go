// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package spam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Rspamd asks an Rspamd normal worker (its /checkv2 endpoint) for a score.
type Rspamd struct {
	URL      string // e.g. http://127.0.0.1:11333
	Password string // sent as the Password header when set
	Client   *http.Client
}

// Check returns Rspamd's score for the message.
func (r *Rspamd) Check(ctx context.Context, m Message) (float64, error) {
	body, err := m.Raw()
	if err != nil {
		return 0, err
	}
	defer body.Close()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(r.URL, "/")+"/checkv2", body)
	if err != nil {
		return 0, err
	}
	if m.RemoteIP != nil {
		req.Header.Set("IP", m.RemoteIP.String())
	}
	if m.Helo != "" {
		req.Header.Set("Helo", m.Helo)
	}
	if m.MailFrom != "" {
		req.Header.Set("From", m.MailFrom)
	}
	for _, rc := range m.Rcpts {
		req.Header.Add("Rcpt", rc)
	}
	if r.Password != "" {
		req.Header.Set("Password", r.Password)
	}
	c := r.Client
	if c == nil {
		c = http.DefaultClient
	}
	res, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("rspamd: %s", res.Status)
	}
	var out struct {
		Score float64 `json:"score"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return 0, err
	}
	return out.Score, nil
}

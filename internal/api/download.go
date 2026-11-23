// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Downloads serves raw messages and attachments over plain HTTP GET, so the
// browser can stream them straight to disk:
//
//	GET /api/messages/{id}/raw
//	GET /api/messages/{id}/parts/{part}[?inline=1]
type Downloads struct {
	Auth *Auth
	Mail *MailServer
}

// Register mounts the handlers on mux.
func (d *Downloads) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/messages/{id}/raw", d.raw)
	mux.HandleFunc("GET /api/messages/{id}/parts/{part}", d.part)
}

func (d *Downloads) open(w http.ResponseWriter, r *http.Request) (io.ReadCloser, store.Message, bool) {
	u, err := d.Auth.User(r.Context(), r.Header)
	if err != nil {
		http.Error(w, "sign in required", http.StatusUnauthorized)
		return nil, store.Message{}, false
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	m, err := d.Mail.Store.Message(r.Context(), u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return nil, m, false
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, m, false
	}
	rc, err := d.Mail.Blobs.Open(u.TenantID, m.BlobHash)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, m, false
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, max-age=3600")
	return rc, m, true
}

func (d *Downloads) raw(w http.ResponseWriter, r *http.Request) {
	rc, m, ok := d.open(w, r)
	if !ok {
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "message-" + strconv.FormatInt(m.ID, 10) + ".eml"}))
	io.Copy(w, rc)
}

// inlineSafe lists types a browser may render in place. SVG and HTML are
// excluded because they can run script.
var inlineSafe = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/avif": true, "application/pdf": true,
}

func (d *Downloads) part(w http.ResponseWriter, r *http.Request) {
	rc, _, ok := d.open(w, r)
	if !ok {
		return
	}
	defer rc.Close()
	hdr, body, err := mail.OpenPart(rc, r.PathValue("part"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct, params, _ := hdr.ContentType()
	_, dparams, _ := hdr.ContentDisposition()
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	name = mail.DecodeHeader(name)
	if name == "" {
		name = "attachment"
	}
	disp := "attachment"
	if r.URL.Query().Get("inline") == "1" && inlineSafe[strings.ToLower(ct)] {
		disp = "inline"
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	io.Copy(w, body)
}

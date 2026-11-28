// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gsoultan/kakarot"
	"github.com/gsoultan/kakarot/transport/httpx"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/preview"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/uploads"
	"github.com/gsoultan/talaria/usecase"
)

// files streams message downloads and takes attachment uploads as raw HTTP,
// so large files never pass through a JSON body:
//
//	POST /api/v1/uploads                     body is the file; X-Filename names it
//	GET  /api/v1/messages/{id}/raw           the message as .eml
//	GET  /api/v1/messages/{id}/parts/{part}  one attachment; ?inline=1 for safe types
//	GET  /api/v1/messages/{id}/parts/{part}/image  an image attachment, redrawn as PNG
type files struct {
	store   *store.Store
	blobs   *blob.Store
	uploads *uploads.Store
}

func (f *files) register(r *httpx.Router) {
	r.HandleFunc("POST /api/v1/uploads", f.upload)
	r.HandleFunc("GET /api/v1/messages/{id}/raw", f.raw)
	r.HandleFunc("GET /api/v1/messages/{id}/parts/{part}", f.part)
	r.HandleFunc("GET /api/v1/messages/{id}/parts/{part}/image", f.image)
}

// image is an attachment's image decoded and drawn again as PNG, for the
// safe preview: whatever else was in the file is left behind.
func (f *files) image(w http.ResponseWriter, r *http.Request) {
	rc, _, ok := f.open(w, r)
	if !ok {
		return
	}
	defer rc.Close()
	_, body, err := mail.OpenPart(rc, r.PathValue("part"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var out bytes.Buffer
	if err := preview.Image(body, &out); err != nil {
		http.Error(w, "not an image that can be previewed", http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(out.Bytes())
}

func signedIn(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	u := usecase.CallerFrom(r.Context()).User
	if u.ID == 0 {
		httpx.WriteError(r.Context(), w, kakarot.E(kakarot.CodeUnauthorized, "sign in required", nil))
		return u, false
	}
	return u, true
}

func (f *files) upload(w http.ResponseWriter, r *http.Request) {
	u, ok := signedIn(w, r)
	if !ok {
		return
	}
	name, _ := url.PathUnescape(r.Header.Get("X-Filename"))
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || strings.ContainsAny(mt, "\r\n") {
		ct = "application/octet-stream"
	}
	if r.ContentLength > f.uploads.MaxSize() {
		httpx.WriteError(r.Context(), w, kakarot.E(kakarot.CodeInvalid, "the file is larger than the message size limit", nil))
		return
	}
	up, err := f.uploads.Put(u.ID, name, ct, r.Body)
	if errors.Is(err, uploads.ErrTooLarge) {
		httpx.WriteError(r.Context(), w, kakarot.E(kakarot.CodeInvalid, err.Error(), err))
		return
	}
	if err != nil {
		httpx.WriteError(r.Context(), w, kakarot.E(kakarot.CodeInternal, "internal error", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(up)
}

func (f *files) open(w http.ResponseWriter, r *http.Request) (io.ReadCloser, store.Message, bool) {
	u, ok := signedIn(w, r)
	if !ok {
		return nil, store.Message{}, false
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	m, err := f.store.Message(r.Context(), u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return nil, m, false
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, m, false
	}
	rc, err := f.blobs.Open(u.TenantID, m.BlobHash)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, m, false
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, max-age=3600")
	return rc, m, true
}

func (f *files) raw(w http.ResponseWriter, r *http.Request) {
	rc, m, ok := f.open(w, r)
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

func (f *files) part(w http.ResponseWriter, r *http.Request) {
	rc, _, ok := f.open(w, r)
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

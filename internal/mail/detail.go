// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/emersion/go-message"
)

// Part is an attachment or inline part of a message.
type Part struct {
	Path        string // "1", "2.1", …
	Filename    string
	ContentType string
	Size        int64 // decoded size, or -1 when not counted
	ContentID   string
	Inline      bool
}

// Detail is a message prepared for reading.
type Detail struct {
	Headers     [][2]string
	Text        string
	HTML        string
	Parts       []Part
	AuthResults string
	ReplyTo     string
}

const maxBody = 2 << 20

// shownHeaders are returned to the client; the raw message is available for
// anything else.
var shownHeaders = map[string]bool{
	"From": true, "To": true, "Cc": true, "Reply-To": true, "Date": true, "Subject": true,
	"List-Unsubscribe": true, "List-Id": true, "Sender": true,
}

// ReadDetail parses a message for display. Text and HTML bodies are capped
// at 2 MiB each; attachments are listed, not read.
func ReadDetail(r io.Reader) (Detail, error) {
	var d Detail
	e, err := message.Read(bufio.NewReaderSize(r, 32<<10))
	if e == nil {
		return d, err
	}
	f := e.Header.Fields()
	for f.Next() {
		k := f.Key()
		if shownHeaders[k] && len(d.Headers) < 50 {
			d.Headers = append(d.Headers, [2]string{k, DecodeHeader(f.Value())})
		}
		if k == "Authentication-Results" && d.AuthResults == "" {
			d.AuthResults = f.Value() // the topmost one is ours
		}
	}
	d.ReplyTo = DecodeHeader(e.Header.Get("Reply-To"))
	parts := 0
	err = walk(e, nil, func(path []int, p *message.Entity) error {
		parts++
		if parts > 200 {
			return errStop
		}
		ct, params, _ := p.Header.ContentType()
		disp, dparams, _ := p.Header.ContentDisposition()
		filename := dparams["filename"]
		if filename == "" {
			filename = params["name"]
		}
		if strings.HasPrefix(ct, "multipart/") {
			return nil
		}
		isBody := disp != "attachment" && filename == "" && (ct == "text/plain" || ct == "text/html")
		if isBody {
			var b strings.Builder
			if ct == "text/plain" && d.Text == "" {
				readCapped(&b, p.Body)
				d.Text = b.String()
				return nil
			}
			if ct == "text/html" && d.HTML == "" {
				readCapped(&b, p.Body)
				d.HTML = b.String()
				return nil
			}
		}
		if len(path) == 0 && ct == "text/plain" {
			return nil
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(p.Body, 64<<20))
		d.Parts = append(d.Parts, Part{
			Path: joinPath(path), Filename: clean(DecodeHeader(filename), 255), ContentType: ct, Size: n,
			ContentID: strings.Trim(p.Header.Get("Content-Id"), "<> "), Inline: disp == "inline" || (disp == "" && p.Header.Get("Content-Id") != ""),
		})
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return d, err
}

var errStop = errors.New("stop")

// OpenPart finds a part by path and returns its header and decoded body.
func OpenPart(r io.Reader, want string) (message.Header, io.Reader, error) {
	e, err := message.Read(bufio.NewReaderSize(r, 32<<10))
	if e == nil {
		return message.Header{}, nil, err
	}
	var hdr message.Header
	var body io.Reader
	err = walk(e, nil, func(path []int, p *message.Entity) error {
		if joinPath(path) == want {
			hdr, body = p.Header, p.Body
			return errStop
		}
		return nil
	})
	if body == nil {
		return hdr, nil, errors.New("part not found")
	}
	return hdr, body, nil
}

// walk visits leaf parts depth-first; path holds 1-based indexes. Unlike
// Entity.Walk it stops early when fn returns an error, so OpenPart can
// return a body that is still readable.
func walk(e *message.Entity, path []int, fn func([]int, *message.Entity) error) error {
	mr := e.MultipartReader()
	if mr == nil {
		return fn(path, e)
	}
	for i := 1; ; i++ {
		p, err := mr.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if p == nil {
				return nil // truncated multipart: keep what we have
			}
		}
		child := append(append([]int(nil), path...), i)
		if err := walk(p, child, fn); err != nil {
			return err
		}
	}
}

func joinPath(p []int) string {
	if len(p) == 0 {
		return "1"
	}
	s := make([]string, len(p))
	for i, n := range p {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ".")
}

func readCapped(b *strings.Builder, r io.Reader) {
	buf, _ := io.ReadAll(io.LimitReader(r, maxBody))
	b.WriteString(strings.ToValidUTF8(string(buf), "�"))
}

// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package preview shows what is in an attachment without opening it: the
// text of documents, PDFs and spreadsheets, the list of files in an
// archive, and images decoded and drawn again so that nothing hidden in
// the original file reaches the browser. Nothing in the file is run.
package preview

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"image"
	_ "image/gif"  // decoders for Image
	_ "image/jpeg" // decoders for Image
	"image/png"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gsoultan/talaria/internal/mail"
)

// Kinds of preview.
const (
	KindText  = "text"  // Text holds the readable text
	KindImage = "image" // fetch the redrawn image
	KindList  = "list"  // Items lists an archive's files
	KindNone  = "none"  // nothing to show; Note says why
)

// Limits.
const (
	MaxInput = 25 << 20
	maxText  = 200 << 10
	maxItems = 500
	maxPixel = 40_000_000 // decoded image size cap, against image bombs
)

// Result is a preview.
type Result struct {
	Kind      string
	Text      string
	Items     []Item
	Note      string
	Truncated bool
	SHA256    string
	Size      int64
}

// Item is a file inside an archive.
type Item struct {
	Name      string
	Size      int64
	Encrypted bool
}

// Risky reports whether a file type can carry active content (macros,
// scripts, exploits), so the webmail offers a preview before a download.
func Risky(name, contentType string) bool {
	e := ext(name)
	switch e {
	case "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "xlam", "ppt", "pptx", "pptm", "ppsm",
		"rtf", "pdf", "htm", "html", "xhtml", "svg", "mht", "mhtml", "zip", "rar", "7z", "gz", "tgz", "tar", "cab", "iso", "img",
		"odt", "ods", "odp", "eml", "msg", "xml", "js", "vbs", "ps1", "bat", "cmd", "exe", "dll", "msi", "lnk", "jar", "hta", "scr":
		return true
	}
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "html") || strings.Contains(ct, "javascript") || ct == "application/octet-stream" && e == ""
}

func ext(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(name[i+1:]))
}

// Of builds a preview of a file.
func Of(name, contentType string, r io.Reader) Result {
	b, _ := io.ReadAll(io.LimitReader(r, MaxInput+1))
	res := Result{Size: int64(len(b))}
	sum := sha256.Sum256(b)
	res.SHA256 = hex.EncodeToString(sum[:])
	if len(b) > MaxInput {
		res.Kind, res.Note = KindNone, "The file is too large to preview."
		return res
	}
	ct := strings.ToLower(contentType)
	e := ext(name)
	switch {
	case isImage(b):
		if cfg, _, err := image.DecodeConfig(bytes.NewReader(b)); err == nil && cfg.Width*cfg.Height <= maxPixel {
			res.Kind = KindImage
			return res
		}
		res.Kind, res.Note = KindNone, "The image is damaged or too large to preview."
	case bytes.HasPrefix(b, []byte("%PDF")):
		res.setText(pdfText(b))
		if res.Text == "" {
			res.Kind, res.Note = KindNone, "No text could be read from this PDF. It may be scanned pages or use an unusual font encoding."
		}
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		res.office(b, e)
	case e == "rtf" || bytes.HasPrefix(b, []byte(`{\rtf`)):
		res.setText(rtfText(b))
	case e == "eml" || ct == "message/rfc822":
		s := mail.Summarize(bytes.NewReader(b))
		res.setText(fmt.Sprintf("From: %s <%s>\nTo: %s\nSubject: %s\n\n%s", s.FromName, s.FromAddr, s.To, s.Subject, s.Text))
	case e == "html" || e == "htm" || strings.Contains(ct, "html"):
		res.setText(mail.HTMLToText(decodeText(b)))
	case e == "svg" || strings.HasPrefix(ct, "text/") || isText(b):
		res.setText(decodeText(b))
	default:
		res.Kind, res.Note = KindNone, "This type of file cannot be previewed."
	}
	return res
}

func (r *Result) setText(s string) {
	s = strings.TrimSpace(strings.ToValidUTF8(s, "�"))
	if len(s) > maxText {
		i := maxText
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s, r.Truncated = s[:i], true
	}
	r.Kind, r.Text = KindText, s
}

func isImage(b []byte) bool {
	return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) || bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}) ||
		bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
}

// isText is true for valid UTF-8 without control characters.
func isText(b []byte) bool {
	if len(b) > 8192 {
		b = b[:8192]
	}
	if !utf8.Valid(b) {
		// It may end mid-rune at the cut.
		for i := 0; i < 3 && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1]
		}
		if !utf8.Valid(b) {
			return false
		}
	}
	for _, r := range string(b) {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' && r != '\f' {
			return false
		}
	}
	return true
}

func decodeText(b []byte) string {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if utf8.Valid(b) {
		return string(b)
	}
	// Latin-1.
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// Image decodes an image and encodes it again as PNG, dropping metadata
// and anything appended to or hidden in the original.
func Image(r io.Reader, w io.Writer) error {
	b, err := io.ReadAll(io.LimitReader(r, MaxInput))
	if err != nil {
		return err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return err
	}
	if cfg.Width*cfg.Height > maxPixel {
		return fmt.Errorf("image too large: %dx%d", cfg.Width, cfg.Height)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(w, img)
}

// office reads Word, Excel, PowerPoint and OpenDocument files, or lists
// any other zip.
func (r *Result) office(b []byte, e string) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		r.Kind, r.Note = KindNone, "The archive is damaged."
		return
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	read := func(name string) []byte {
		f := files[name]
		if f == nil || f.UncompressedSize64 > 50<<20 {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		defer rc.Close()
		out, _ := io.ReadAll(io.LimitReader(rc, 50<<20))
		return out
	}
	var note string
	if files["word/vbaProject.bin"] != nil || files["xl/vbaProject.bin"] != nil || files["ppt/vbaProject.bin"] != nil {
		note = "This document contains macros. They are not run in the preview."
	}
	switch {
	case files["word/document.xml"] != nil:
		r.setText(xmlText(read("word/document.xml"), "t", "p", "tab", "br"))
	case files["xl/workbook.xml"] != nil:
		r.setText(xlsxText(files, read))
	case files["ppt/presentation.xml"] != nil:
		var names []string
		for n := range files {
			if strings.HasPrefix(n, "ppt/slides/slide") && strings.HasSuffix(n, ".xml") {
				names = append(names, n)
			}
		}
		sort.Slice(names, func(i, j int) bool { return slideNum(names[i]) < slideNum(names[j]) })
		var sb strings.Builder
		for i, n := range names {
			fmt.Fprintf(&sb, "— Slide %d —\n%s\n\n", i+1, strings.TrimSpace(xmlText(read(n), "t", "p", "", "br")))
		}
		r.setText(sb.String())
	case files["content.xml"] != nil && files["mimetype"] != nil:
		r.setText(xmlText(read("content.xml"), "span|p|h|s|tab|line-break", "p|h", "tab", "line-break"))
	default:
		r.Kind = KindList
		for i, f := range zr.File {
			if i >= maxItems {
				r.Truncated = true
				break
			}
			if strings.HasSuffix(f.Name, "/") {
				continue
			}
			r.Items = append(r.Items, Item{Name: f.Name, Size: int64(f.UncompressedSize64), Encrypted: f.Flags&1 != 0})
		}
	}
	if note != "" {
		r.Note = note
	}
}

func slideNum(n string) int {
	v, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path.Base(n), "slide"), ".xml"))
	return v
}

// xmlText collects the character data of elements named text (local
// names, | separated), ending a line after each para element and putting
// a tab or line break for tab and br elements.
func xmlText(b []byte, text, para, tab, br string) string {
	in := func(set, name string) bool {
		if set == "" {
			return false
		}
		for _, s := range strings.Split(set, "|") {
			if s == name {
				return true
			}
		}
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	var sb strings.Builder
	depth := 0
	for sb.Len() < maxText {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case in(text, t.Name.Local):
				depth++
			case in(tab, t.Name.Local):
				sb.WriteByte('\t')
			case in(br, t.Name.Local):
				sb.WriteByte('\n')
			}
		case xml.EndElement:
			if in(text, t.Name.Local) && depth > 0 {
				depth--
			}
			if in(para, t.Name.Local) {
				sb.WriteByte('\n')
			}
		case xml.CharData:
			if depth > 0 {
				sb.Write(t)
			}
		}
	}
	return sb.String()
}

// xlsxText renders each sheet as tab-separated rows.
func xlsxText(files map[string]*zip.File, read func(string) []byte) string {
	var shared []string
	if b := read("xl/sharedStrings.xml"); b != nil {
		d := xml.NewDecoder(bytes.NewReader(b))
		var cur strings.Builder
		inSI, inT := false, false
		for {
			tok, err := d.Token()
			if err != nil {
				break
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "si" {
					inSI = true
					cur.Reset()
				} else if t.Name.Local == "t" && inSI {
					inT = true
				}
			case xml.EndElement:
				if t.Name.Local == "si" {
					shared = append(shared, cur.String())
					inSI = false
				} else if t.Name.Local == "t" {
					inT = false
				}
			case xml.CharData:
				if inT {
					cur.Write(t)
				}
			}
		}
	}
	var sheets []string
	for n := range files {
		if strings.HasPrefix(n, "xl/worksheets/sheet") && strings.HasSuffix(n, ".xml") {
			sheets = append(sheets, n)
		}
	}
	sort.Slice(sheets, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sheets[i], "xl/worksheets/sheet"), ".xml"))
		b, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sheets[j], "xl/worksheets/sheet"), ".xml"))
		return a < b
	})
	var sb strings.Builder
	for i, n := range sheets {
		fmt.Fprintf(&sb, "— Sheet %d —\n", i+1)
		d := xml.NewDecoder(bytes.NewReader(read(n)))
		var row []string
		cellType, inV, inIS := "", false, false
		var val strings.Builder
		rows := 0
		for rows < 1000 && sb.Len() < maxText {
			tok, err := d.Token()
			if err != nil {
				break
			}
			switch t := tok.(type) {
			case xml.StartElement:
				switch t.Name.Local {
				case "row":
					row = row[:0]
				case "c":
					cellType = ""
					for _, a := range t.Attr {
						if a.Name.Local == "t" {
							cellType = a.Value
						}
					}
					val.Reset()
				case "v":
					inV = true
				case "is":
					inIS = true
				}
			case xml.EndElement:
				switch t.Name.Local {
				case "v":
					inV = false
				case "is":
					inIS = false
				case "c":
					v := val.String()
					if cellType == "s" {
						if k, err := strconv.Atoi(v); err == nil && k >= 0 && k < len(shared) {
							v = shared[k]
						}
					}
					row = append(row, v)
				case "row":
					sb.WriteString(strings.Join(row, "\t") + "\n")
					rows++
				}
			case xml.CharData:
				if inV || inIS {
					val.Write(t)
				}
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// rtfText strips RTF control words and groups that hold no body text.
func rtfText(b []byte) string {
	var sb strings.Builder
	skip := []bool{false}
	s := string(b)
	for i := 0; i < len(s) && sb.Len() < maxText; i++ {
		c := s[i]
		switch c {
		case '{':
			skip = append(skip, skip[len(skip)-1])
		case '}':
			if len(skip) > 1 {
				skip = skip[:len(skip)-1]
			}
		case '\\':
			j := i + 1
			if j < len(s) && (s[j] == '\\' || s[j] == '{' || s[j] == '}') {
				if !skip[len(skip)-1] {
					sb.WriteByte(s[j])
				}
				i = j
				continue
			}
			if j < len(s) && s[j] == '*' {
				skip[len(skip)-1] = true
				i = j
				continue
			}
			if j < len(s) && s[j] == '\'' && j+2 < len(s) {
				if v, err := strconv.ParseUint(s[j+1:j+3], 16, 8); err == nil && !skip[len(skip)-1] {
					sb.WriteRune(rune(v))
				}
				i = j + 2
				continue
			}
			k := j
			for k < len(s) && unicode.IsLetter(rune(s[k])) {
				k++
			}
			word := s[j:k]
			for k < len(s) && (s[k] == '-' || unicode.IsDigit(rune(s[k]))) {
				k++
			}
			if k < len(s) && s[k] == ' ' {
				k++
			}
			switch word {
			case "fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "header", "footer", "listtable", "listoverridetable", "themedata", "datastore":
				skip[len(skip)-1] = true
			case "par", "line", "row":
				if !skip[len(skip)-1] {
					sb.WriteByte('\n')
				}
			case "tab", "cell":
				if !skip[len(skip)-1] {
					sb.WriteByte('\t')
				}
			}
			i = k - 1
		case '\r', '\n':
		default:
			if !skip[len(skip)-1] {
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}

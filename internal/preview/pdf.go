// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package preview

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var streamRe = regexp.MustCompile(`(?s)<<(.{0,1000}?)>>\s*stream\r?\n`)

// pdfText reads the text of a PDF's content streams: the strings shown by
// Tj, TJ, ' and ". Fonts with their own encodings (common for CJK text and
// subset fonts) come out as nonsense, which is detected and dropped.
func pdfText(b []byte) string {
	var sb strings.Builder
	for _, m := range streamRe.FindAllSubmatchIndex(b, 5000) {
		dict := string(b[m[2]:m[3]])
		start := m[1]
		end := bytes.Index(b[start:], []byte("endstream"))
		if end < 0 {
			break
		}
		data := b[start : start+end]
		if strings.Contains(dict, "/Subtype/Image") || strings.Contains(dict, "/Subtype /Image") || strings.Contains(dict, "/Type/XRef") || strings.Contains(dict, "/Type /XRef") {
			continue
		}
		if strings.Contains(dict, "/FlateDecode") {
			zr, err := zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				continue
			}
			data, _ = io.ReadAll(io.LimitReader(zr, 20<<20))
			zr.Close()
		} else if strings.Contains(dict, "/Filter") {
			continue // other encodings are not text we can read
		}
		if !bytes.Contains(data, []byte("BT")) {
			continue
		}
		contentText(&sb, data)
		if sb.Len() > maxText {
			break
		}
	}
	s := sb.String()
	if !readable(s) {
		return ""
	}
	return s
}

// contentText runs the text operators of one content stream.
func contentText(sb *strings.Builder, d []byte) {
	var ops []string // strings waiting for their operator
	var nums []float64
	for i := 0; i < len(d); {
		c := d[i]
		switch {
		case c == '(':
			s, n := pdfString(d[i:])
			ops = append(ops, s)
			i += n
			continue
		case c == '<' && i+1 < len(d) && d[i+1] != '<':
			j := bytes.IndexByte(d[i:], '>')
			if j < 0 {
				return
			}
			ops = append(ops, hexString(string(d[i+1:i+j])))
			i += j + 1
			continue
		case c == '[' || c == ']':
			i++
			continue
		case c == '%':
			for i < len(d) && d[i] != '\n' && d[i] != '\r' {
				i++
			}
			continue
		case unicode.IsSpace(rune(c)):
			i++
			continue
		}
		j := i
		for j < len(d) && !unicode.IsSpace(rune(d[j])) && !strings.ContainsRune("()<>[]/%", rune(d[j])) {
			j++
		}
		if j == i {
			j++
		}
		tok := string(d[i:j])
		i = j
		if f, err := strconv.ParseFloat(tok, 64); err == nil {
			nums = append(nums, f)
			if len(nums) > 8 {
				nums = nums[1:]
			}
			continue
		}
		switch tok {
		case "Tj", "TJ":
			for _, s := range ops {
				sb.WriteString(s)
			}
		case "'", `"`:
			sb.WriteByte('\n')
			for _, s := range ops {
				sb.WriteString(s)
			}
		case "T*", "ET":
			sb.WriteByte('\n')
		case "Td", "TD":
			if len(nums) >= 2 && nums[len(nums)-1] != 0 {
				sb.WriteByte('\n')
			} else if len(nums) >= 2 && nums[len(nums)-2] > 0 {
				sb.WriteByte(' ')
			}
		case "Tm":
			sb.WriteByte('\n')
		}
		if tok != "" && tok[0] != '/' {
			ops = ops[:0]
			nums = nums[:0]
		}
	}
}

// pdfString decodes a literal string starting at d[0] == '('.
func pdfString(d []byte) (string, int) {
	var sb strings.Builder
	depth := 0
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch c {
		case '(':
			if depth > 0 {
				sb.WriteByte(c)
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				return decodePDFText(sb.String()), i + 1
			}
			sb.WriteByte(c)
		case '\\':
			i++
			if i >= len(d) {
				break
			}
			switch e := d[i]; e {
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'b', 'f':
			case '\r', '\n':
			default:
				if e >= '0' && e <= '7' {
					j := i
					for j < len(d) && j < i+3 && d[j] >= '0' && d[j] <= '7' {
						j++
					}
					v, _ := strconv.ParseUint(string(d[i:j]), 8, 8)
					sb.WriteByte(byte(v))
					i = j - 1
				} else {
					sb.WriteByte(e)
				}
			}
		default:
			sb.WriteByte(c)
		}
	}
	return decodePDFText(sb.String()), len(d)
}

func hexString(h string) string {
	h = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, h)
	if len(h)%2 == 1 {
		h += "0"
	}
	b := make([]byte, 0, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		v, err := strconv.ParseUint(h[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		b = append(b, byte(v))
	}
	return decodePDFText(string(b))
}

// decodePDFText reads UTF-16BE strings (with a byte-order mark) and treats
// the rest as Latin-1, close enough to PDFDocEncoding for text.
func decodePDFText(s string) string {
	if strings.HasPrefix(s, "\xfe\xff") {
		var r []rune
		for i := 2; i+1 < len(s); i += 2 {
			r = append(r, rune(s[i])<<8|rune(s[i+1]))
		}
		return string(r)
	}
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

// readable is false when most of the text is control characters or
// symbols, as from a font with its own encoding.
func readable(s string) bool {
	good, total := 0, 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		total++
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsPunct(r) {
			good++
		}
	}
	return total > 0 && good*10 >= total*7
}

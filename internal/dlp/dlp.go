// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package dlp finds sensitive data in outgoing mail: card numbers, bank
// accounts, national ID numbers, and whatever a tenant describes with its
// own patterns or keywords. It reads the subject, the body and the text
// of attachments.
package dlp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"

	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/preview"
)

// Detectors.
const (
	CreditCard = "credit_card"
	IBAN       = "iban"
	USSSN      = "us_ssn"
	IDNIK      = "id_nik" // Indonesian national ID (NIK)
	Pattern    = "pattern"
	Keywords   = "keywords"
)

// Detectors lists the detectors with a description, for the admin.
var Detectors = []struct{ Kind, Label string }{
	{CreditCard, "Payment card numbers (checked with the Luhn digit)"},
	{IBAN, "IBAN bank account numbers (checked with their check digits)"},
	{USSSN, "US Social Security numbers"},
	{IDNIK, "Indonesian national ID numbers (NIK)"},
	{Pattern, "A regular expression of your own"},
	{Keywords, "Any of a list of words or phrases"},
}

// Actions, weakest first.
const (
	Notify  = "notify"  // send, and tell the policy's contact
	Encrypt = "encrypt" // send only over verified TLS
	Warn    = "warn"    // ask the sender to confirm in the webmail
	Block   = "block"   // refuse
)

var strength = map[string]int{Notify: 1, Encrypt: 2, Warn: 3, Block: 4}

// Stronger reports whether action a outranks b.
func Stronger(a, b string) bool { return strength[a] > strength[b] }

// Policy is one rule.
type Policy struct {
	ID       int64
	Name     string
	Detector string
	// Pattern is the regular expression (Pattern) or the words, one per
	// line or comma separated (Keywords).
	Pattern  string
	MinCount int
	Action   string
	// ExternalOnly applies the policy only to mail leaving the tenant's
	// domains.
	ExternalOnly bool
	Notify       string
}

// Validate checks a policy can run.
func (p Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name: give the policy a name")
	}
	if _, ok := strength[p.Action]; !ok {
		return fmt.Errorf("action: use block, warn, encrypt or notify")
	}
	switch p.Detector {
	case CreditCard, IBAN, USSSN, IDNIK:
	case Pattern:
		if _, err := regexp.Compile(p.Pattern); err != nil || strings.TrimSpace(p.Pattern) == "" {
			return fmt.Errorf("pattern: not a valid regular expression")
		}
	case Keywords:
		if len(keywords(p.Pattern)) == 0 {
			return fmt.Errorf("pattern: list at least one word or phrase")
		}
	default:
		return fmt.Errorf("detector: unknown detector %q", p.Detector)
	}
	return nil
}

// Match is a policy that matched.
type Match struct {
	Policy  Policy
	Count   int
	Samples []string // masked, safe to show an admin
}

// Evaluate runs the policies over text and returns those that matched,
// strongest action first.
func Evaluate(text string, policies []Policy) []Match {
	var out []Match
	for _, p := range policies {
		found := find(p, text)
		min := p.MinCount
		if min < 1 {
			min = 1
		}
		if len(found) >= min {
			m := Match{Policy: p, Count: len(found)}
			for i, f := range found {
				if i == 3 {
					break
				}
				m.Samples = append(m.Samples, mask(f))
			}
			out = append(out, m)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && Stronger(out[j].Policy.Action, out[j-1].Policy.Action); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

var (
	cardRe = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)
	ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	ssnRe  = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)
	nikRe  = regexp.MustCompile(`\b\d{16}\b`)
)

// find returns the distinct values a policy's detector finds.
func find(p Policy, text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] && len(out) < 1000 {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch p.Detector {
	case CreditCard:
		for _, m := range cardRe.FindAllString(text, -1) {
			d := digits(m)
			if len(d) >= 13 && len(d) <= 19 && luhn(d) && cardPrefix(d) {
				add(d)
			}
		}
	case IBAN:
		for _, m := range ibanRe.FindAllString(text, -1) {
			if s := strings.ReplaceAll(m, " ", ""); ibanValid(s) {
				add(s)
			}
		}
	case USSSN:
		for _, m := range ssnRe.FindAllStringSubmatch(text, -1) {
			if m[1] != "000" && m[1] != "666" && m[1][0] != '9' && m[2] != "00" && m[3] != "0000" {
				add(m[0])
			}
		}
	case IDNIK:
		for _, m := range nikRe.FindAllString(text, -1) {
			if nikValid(m) {
				add(m)
			}
		}
	case Pattern:
		if re, err := regexp.Compile(p.Pattern); err == nil {
			for _, m := range re.FindAllString(text, 1000) {
				add(m)
			}
		}
	case Keywords:
		lower := strings.ToLower(text)
		for _, k := range keywords(p.Pattern) {
			for i, off := 0, 0; i < 1000; i++ {
				j := strings.Index(lower[off:], k)
				if j < 0 {
					break
				}
				start, end := off+j, off+j+len(k)
				if boundary(lower, start-1) && boundary(lower, end) {
					add(fmt.Sprintf("%s#%d", k, start))
				}
				off = end
			}
		}
	}
	return out
}

func keywords(s string) []string {
	var out []string
	for _, k := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func boundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	c := rune(s[i])
	return !unicode.IsLetter(c) && !unicode.IsDigit(c)
}

func digits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// cardPrefix keeps numbers that start like a payment card (Visa,
// Mastercard, Amex, Discover, JCB, UnionPay, Diners, Maestro).
func cardPrefix(d string) bool {
	two, _ := strconv.Atoi(d[:2])
	four, _ := strconv.Atoi(d[:4])
	switch {
	case d[0] == '4':
		return true
	case two >= 51 && two <= 55, four >= 2221 && four <= 2720:
		return true
	case two == 34 || two == 37 || two == 36 || two == 38 || two == 62 || two == 35:
		return true
	case strings.HasPrefix(d, "6011") || strings.HasPrefix(d, "65") || two == 50 || two == 56 || two == 57 || two == 58 || two == 67:
		return true
	}
	return false
}

func ibanValid(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	r := s[4:] + s[:4]
	var b strings.Builder
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteString(strconv.Itoa(int(c-'A') + 10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// nikValid checks the parts of a NIK: province code, then a birth date
// (day plus 40 for women) in digits 7 to 12.
func nikValid(s string) bool {
	prov, _ := strconv.Atoi(s[:2])
	day, _ := strconv.Atoi(s[6:8])
	month, _ := strconv.Atoi(s[8:10])
	if day > 40 {
		day -= 40
	}
	return prov >= 11 && prov <= 94 && day >= 1 && day <= 31 && month >= 1 && month <= 12 && s[12:] != "0000"
}

// mask hides all but the edges of a value.
func mask(s string) string {
	if i := strings.LastIndexByte(s, '#'); i > 0 { // keyword#offset
		return s[:i]
	}
	r := []rune(s)
	if len(r) <= 6 {
		return strings.Repeat("•", len(r))
	}
	keep := 4
	if len(r) < 10 {
		keep = 2
	}
	return strings.Repeat("•", len(r)-keep) + string(r[len(r)-keep:])
}

// Text returns what the policies look at: the subject, the text of the
// body, and the text of each attachment that can be read.
func Text(r io.Reader) string {
	e, _ := message.Read(bufio.NewReaderSize(r, 32<<10))
	if e == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(mail.DecodeHeader(e.Header.Get("Subject")))
	sb.WriteByte('\n')
	n := 0
	var walk func(e *message.Entity)
	walk = func(e *message.Entity) {
		if mr := e.MultipartReader(); mr != nil {
			for {
				p, err := mr.NextPart()
				if p == nil || err == io.EOF {
					return
				}
				walk(p)
				if err != nil {
					return
				}
			}
		}
		if n++; n > 100 || sb.Len() > 4<<20 {
			return
		}
		ct, params, _ := e.Header.ContentType()
		_, dparams, _ := e.Header.ContentDisposition()
		name := dparams["filename"]
		if name == "" {
			name = params["name"]
		}
		var body bytes.Buffer
		io.Copy(&body, io.LimitReader(e.Body, preview.MaxInput))
		switch {
		case name == "" && ct == "text/html":
			sb.WriteString(mail.HTMLToText(body.String()))
		case name == "" && strings.HasPrefix(ct, "text/"):
			sb.Write(body.Bytes())
		default:
			if p := preview.Of(name, ct, &body); p.Kind == preview.KindText {
				sb.WriteString(p.Text)
			}
		}
		sb.WriteByte('\n')
	}
	walk(e)
	return sb.String()
}

// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package spam scores inbound mail. A message gets points from a few rules
// that need no outside service (sender authentication, header and content
// tells), optionally from Rspamd, and, for each recipient, from a Bayesian
// filter that learns from what that person moves into and out of Junk.
//
// Scores follow the SpamAssassin habit: around 0 is normal mail, Junk
// starts at 6 by default, and very high scores are refused outright.
package spam

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/gsoultan/talaria/internal/store"
)

// Config sets the thresholds.
type Config struct {
	// JunkScore files a message in Junk at or above it. Default 6.
	JunkScore float64
	// RejectScore refuses a message during SMTP at or above it, before the
	// per-user filter runs. Default 15; 0 or less never refuses.
	RejectScore float64
	// Rspamd, when set, adds Rspamd's score.
	Rspamd *Rspamd
}

// Scorer scores messages. It is safe for concurrent use.
type Scorer struct {
	cfg Config
	st  *store.Store
	log *slog.Logger
}

// New returns a scorer.
func New(cfg Config, st *store.Store, log *slog.Logger) *Scorer {
	if cfg.JunkScore == 0 {
		cfg.JunkScore = 6
	}
	return &Scorer{cfg: cfg, st: st, log: log}
}

// JunkScore is the Junk threshold.
func (s *Scorer) JunkScore() float64 { return s.cfg.JunkScore }

// Rejects reports whether a score is high enough to refuse the message.
func (s *Scorer) Rejects(score float64) bool {
	return s.cfg.RejectScore > 0 && score >= s.cfg.RejectScore
}

// Message is what the scorer looks at.
type Message struct {
	RemoteIP net.IP // nil when the message did not come over SMTP
	Helo     string
	MailFrom string
	Rcpts    []string
	BadHelo  bool
	NoRDNS   bool

	Auth      int64 // store.Auth* bits
	AuthFail  bool  // SPF or DMARC failed outright
	Subject   string
	FromName  string
	FromAddr  string
	MessageID string
	SentDate  int64
	Text      string
	// Raw returns the whole message, for Rspamd.
	Raw func() (io.ReadCloser, error)
}

// Result is a score and the rules that made it.
type Result struct {
	Score   float64
	Symbols []string
}

func (r *Result) add(points float64, name string) {
	r.Score += points
	r.Symbols = append(r.Symbols, fmt.Sprintf("%s(%+.1f)", name, points))
}

// Header formats the result for an X-Spam header.
func (r Result) Header() string {
	return fmt.Sprintf("score=%.1f tests=%s", r.Score, strings.Join(r.Symbols, ","))
}

var (
	urlRe       = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"']+`)
	shorteners  = []string{"bit.ly/", "tinyurl.com/", "t.co/", "goo.gl/", "ow.ly/", "is.gd/", "cutt.ly/", "rebrand.ly/"}
	spamPhrases = []string{
		"verify your account", "account has been suspended", "confirm your password", "unusual sign-in activity",
		"you have won", "claim your prize", "wire transfer", "bitcoin", "crypto investment", "act now",
		"limited time offer", "100% free", "risk-free", "no credit check", "lowest price", "double your",
		"dear beneficiary", "inheritance", "next of kin", "urgent reply",
	}
)

// Score runs the rules that do not depend on the recipient, and Rspamd.
func (s *Scorer) Score(ctx context.Context, m Message) Result {
	var r Result
	switch {
	case m.Auth&store.AuthDMARCPass != 0:
		r.add(-1.5, "DMARC_PASS")
	case m.Auth&store.AuthDKIMPass != 0:
		r.add(-1, "DKIM_PASS")
	case m.Auth&store.AuthSPFPass != 0:
		r.add(-0.5, "SPF_PASS")
	case m.RemoteIP != nil:
		r.add(1.5, "NO_AUTH")
	}
	if m.AuthFail {
		r.add(4, "AUTH_FAIL")
	}
	if m.BadHelo {
		r.add(1.5, "BAD_HELO")
	}
	if m.NoRDNS {
		r.add(1, "NO_RDNS")
	}
	if m.MessageID == "" {
		r.add(1, "MISSING_MID")
	}
	if m.SentDate == 0 {
		r.add(1, "MISSING_DATE")
	}
	subj := strings.TrimSpace(m.Subject)
	if subj == "" {
		r.add(1, "EMPTY_SUBJECT")
	} else if shouting(subj) {
		r.add(1.5, "SUBJ_ALL_CAPS")
	}
	if strings.Contains(m.FromName, "@") && !strings.Contains(strings.ToLower(m.FromName), strings.ToLower(m.FromAddr)) {
		// "PayPal <service@paypal.com>" <x@elsewhere.example>
		r.add(2.5, "FROM_NAME_HAS_ADDR")
	}
	lower := strings.ToLower(subj + "\n" + m.Text)
	hits := 0
	for _, p := range spamPhrases {
		if strings.Contains(lower, p) {
			hits++
		}
	}
	if hits > 0 {
		r.add(math.Min(float64(hits), 4)*0.8, "SPAM_PHRASES")
	}
	urls := urlRe.FindAllString(m.Text, 200)
	if len(urls) > 25 {
		r.add(1, "MANY_LINKS")
	}
	for _, u := range urls {
		lu := strings.ToLower(u)
		if slices.ContainsFunc(shorteners, func(sh string) bool { return strings.Contains(lu, "://"+sh) || strings.Contains(lu, "://www."+sh) }) {
			r.add(1, "URL_SHORTENER")
			break
		}
	}
	for _, u := range urls {
		if host := hostOf(u); net.ParseIP(host) != nil {
			r.add(2, "URL_IP_HOST")
			break
		}
	}
	if s.cfg.Rspamd != nil && m.Raw != nil {
		if score, err := s.cfg.Rspamd.Check(ctx, m); err != nil {
			s.log.Warn("rspamd", "err", err)
		} else {
			r.add(score, "RSPAMD")
		}
	}
	return r
}

func hostOf(u string) string {
	u = u[strings.Index(u, "://")+3:]
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		u = u[i+1:]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(u, "[]")
}

// shouting is a subject of at least 10 letters, all capitals.
func shouting(s string) bool {
	letters, upper := 0, 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	return letters >= 10 && upper == letters
}

// Tokens returns the distinct hashed words of a message for the Bayesian
// filter: subject words are kept apart from body words, and the sender's
// domain is a token of its own.
func Tokens(subject, fromAddr, text string) []int64 {
	seen := map[int64]bool{}
	var out []int64
	add := func(prefix, w string) {
		if len(out) >= 1500 {
			return
		}
		h := fnv.New64a()
		h.Write([]byte(prefix))
		h.Write([]byte(w))
		t := int64(h.Sum64())
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	words := func(s string) []string {
		return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '$' && r != '\'' && r != '-'
		})
	}
	for _, w := range words(subject) {
		if len(w) >= 2 && len(w) <= 30 {
			add("s:", w)
		}
	}
	if i := strings.LastIndexByte(fromAddr, '@'); i >= 0 {
		add("d:", strings.ToLower(fromAddr[i+1:]))
	}
	if len(text) > 32<<10 {
		text = text[:32<<10]
	}
	for _, w := range words(text) {
		if len(w) >= 3 && len(w) <= 30 {
			add("", w)
		}
	}
	for _, u := range urlRe.FindAllString(text, 50) {
		add("u:", strings.ToLower(hostOf(u)))
	}
	return out
}

// Minimum training before the per-user filter has a say.
const minTrained = 20

// Bayes scores a message for one recipient from what they trained. It
// returns 0 until the user has moved enough mail in both directions.
func (s *Scorer) Bayes(ctx context.Context, userID int64, tokens []int64) (float64, string) {
	nSpam, nHam, counts, err := s.st.BayesCounts(ctx, userID, tokens)
	if err != nil {
		s.log.Warn("bayes", "err", err)
		return 0, ""
	}
	if nSpam < minTrained || nHam < minTrained {
		return 0, ""
	}
	p := probability(counts, nSpam, nHam)
	switch {
	case p >= 0.99:
		return 5, "BAYES_99(+5.0)"
	case p >= 0.9:
		return 3, "BAYES_90(+3.0)"
	case p >= 0.7:
		return 1, "BAYES_70(+1.0)"
	case p <= 0.01:
		return -4, "BAYES_01(-4.0)"
	case p <= 0.1:
		return -2, "BAYES_10(-2.0)"
	}
	return 0, ""
}

// probability combines the most telling words with Robinson's method and
// Fisher's chi-square: near 1 is spam, near 0 is ham.
func probability(counts map[int64][2]int, nSpam, nHam int) float64 {
	const s, x = 1.0, 0.5 // strength and prior of words seen rarely
	var ps []float64
	for _, c := range counts {
		n := float64(c[0] + c[1])
		if n == 0 {
			continue
		}
		bs := float64(c[0]) / float64(nSpam)
		bh := float64(c[1]) / float64(nHam)
		p := bs / (bs + bh)
		f := (s*x + n*p) / (s + n)
		ps = append(ps, f)
	}
	if len(ps) == 0 {
		return 0.5
	}
	// The 30 words furthest from neutral.
	sort.Slice(ps, func(i, j int) bool { return math.Abs(ps[i]-0.5) > math.Abs(ps[j]-0.5) })
	if len(ps) > 30 {
		ps = ps[:30]
	}
	var lnP, lnQ float64
	for _, f := range ps {
		f = math.Min(math.Max(f, 0.0001), 0.9999)
		lnP += math.Log(1 - f)
		lnQ += math.Log(f)
	}
	n := len(ps)
	spamminess := 1 - chi2Q(-2*lnP, 2*n)
	hamminess := 1 - chi2Q(-2*lnQ, 2*n)
	return (1 + spamminess - hamminess) / 2
}

// chi2Q is the probability that chi-square with v (even) degrees of
// freedom is at least x2.
func chi2Q(x2 float64, v int) float64 {
	m := x2 / 2
	sum := math.Exp(-m)
	term := sum
	for i := 1; i < v/2; i++ {
		term *= m / float64(i)
		sum += term
	}
	return math.Min(sum, 1)
}

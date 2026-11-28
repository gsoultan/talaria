// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package dlp

import (
	"encoding/base64"
	"strings"
	"testing"
)

func names(ms []Match) string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Policy.Name)
	}
	return strings.Join(out, ",")
}

func TestDetectors(t *testing.T) {
	cases := []struct {
		detector, pattern, text string
		want                    int
	}{
		{CreditCard, "", "card 4111 1111 1111 1111 and 5500-0000-0000-0004", 2},
		{CreditCard, "", "4111 1111 1111 1112 fails Luhn, 1234567812345670 has no card prefix", 0},
		{CreditCard, "", "order 4111111111111111 twice 4111-1111-1111-1111", 1},
		{IBAN, "", "pay to DE89 3704 0044 0532 0130 00 or GB82WEST12345698765432", 2},
		{IBAN, "", "DE89 3704 0044 0532 0130 01 has a bad check", 0},
		{USSSN, "", "SSN 123-45-6789, not 000-12-3456 or 900-12-3456", 1},
		{IDNIK, "", "NIK 3171014509900003 ok, 9971014509900003 bad province", 1},
		{Pattern, `PRJ-\d{4}`, "codes PRJ-1234 and PRJ-9876 and PRJ-12", 2},
		{Keywords, "project falcon\nconfidential", "Project Falcon is CONFIDENTIAL; unconfidential is not a match", 2},
	}
	for _, c := range cases {
		p := Policy{Name: c.detector, Detector: c.detector, Pattern: c.pattern, MinCount: 1, Action: Block}
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", c.detector, err)
		}
		got := 0
		if ms := Evaluate(c.text, []Policy{p}); len(ms) == 1 {
			got = ms[0].Count
		}
		if got != c.want {
			t.Errorf("%s on %q: %d, want %d", c.detector, c.text, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Policy{
		{Name: "", Detector: CreditCard, Action: Block},
		{Name: "x", Detector: CreditCard, Action: "drop"},
		{Name: "x", Detector: "dna", Action: Block},
		{Name: "x", Detector: Pattern, Pattern: "(", Action: Block},
		{Name: "x", Detector: Keywords, Pattern: " , \n", Action: Block},
	}
	for _, p := range bad {
		if p.Validate() == nil {
			t.Errorf("%+v should not validate", p)
		}
	}
}

func TestEvaluateOrderMinCountMask(t *testing.T) {
	text := "4111 1111 1111 1111 and secret"
	ps := []Policy{
		{ID: 1, Name: "notify", Detector: Keywords, Pattern: "secret", MinCount: 1, Action: Notify},
		{ID: 2, Name: "two cards", Detector: CreditCard, MinCount: 2, Action: Block},
		{ID: 3, Name: "warn card", Detector: CreditCard, MinCount: 1, Action: Warn},
		{ID: 4, Name: "tls", Detector: Keywords, Pattern: "secret", MinCount: 1, Action: Encrypt},
	}
	ms := Evaluate(text, ps)
	if got := names(ms); got != "warn card,tls,notify" {
		t.Fatalf("order: %s", got)
	}
	if s := ms[0].Samples[0]; s != "••••••••••••1111" || strings.Contains(s, "4111") {
		t.Fatalf("mask: %q", s)
	}
	if ms[2].Samples[0] != "secret" {
		t.Fatalf("keyword sample: %q", ms[2].Samples)
	}
	if !Stronger(Block, Warn) || Stronger(Notify, Encrypt) {
		t.Fatal("Stronger")
	}
}

func TestTextReadsAttachments(t *testing.T) {
	att := base64.StdEncoding.EncodeToString([]byte("IBAN GB82WEST12345698765432\n"))
	msg := "From: a@x.example\r\nTo: b@y.example\r\nSubject: =?utf-8?q?Q3_numbers?=\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n" +
		"--b\r\nContent-Type: text/plain; name=acct.txt\r\nContent-Disposition: attachment; filename=acct.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n" + att + "\r\n" +
		"--b--\r\n"
	text := Text(strings.NewReader(msg))
	for _, want := range []string{"Q3 numbers", "See attached.", "GB82WEST12345698765432"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	if ms := Evaluate(text, []Policy{{Name: "iban", Detector: IBAN, MinCount: 1, Action: Block}}); len(ms) != 1 {
		t.Fatal("attachment IBAN not found")
	}
}

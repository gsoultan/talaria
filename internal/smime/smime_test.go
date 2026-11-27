// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

type pki struct {
	ca       *x509.Certificate
	caKey    *rsa.PrivateKey
	roots    *x509.CertPool
	leaf     *x509.Certificate
	leafKey  *rsa.PrivateKey
	serialNo int64
}

func newPKI(t *testing.T, email string, usage x509.ExtKeyUsage) *pki {
	t.Helper()
	p := &pki{}
	p.caKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, caT, caT, &p.caKey.PublicKey, p.caKey)
	p.ca, _ = x509.ParseCertificate(der)
	p.roots = x509.NewCertPool()
	p.roots.AddCert(p.ca)
	p.leaf, p.leafKey = p.issue(t, email, usage, time.Now().Add(24*time.Hour))
	return p
}

func (p *pki) issue(t *testing.T, email string, usage x509.ExtKeyUsage, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	p.serialNo++
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100 + p.serialNo), Subject: pkix.Name{CommonName: email}, EmailAddresses: []string{email},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

const inner = "Content-Type: text/plain; charset=utf-8\r\n\r\nPay the invoice by Friday.\r\n"

func (p *pki) sign(t *testing.T, content string, detached bool) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(p.leaf, p.leafKey, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	if detached {
		sd.Detach()
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func wrap64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	return out.String() + s + "\r\n"
}

func multipartSigned(from string, content string, sig []byte) string {
	return "From: " + from + "\r\nTo: b@y.example\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"b1\"\r\n\r\n" +
		"This is an S/MIME signed message\r\n--b1\r\n" + content + "\r\n--b1\r\n" +
		"Content-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=smime.p7s\r\n\r\n" + wrap64(sig) + "--b1--\r\n"
}

func TestCheckSigned(t *testing.T) {
	p := newPKI(t, "ana@x.example", x509.ExtKeyUsageEmailProtection)
	c := &Checker{Roots: p.roots}
	sig := p.sign(t, inner, true)

	st := c.Check(strings.NewReader(multipartSigned("Ana <Ana@X.example>", inner, sig)))
	if !st.Signed || !st.Verified || st.Signer != "ana@x.example" || st.Problem != "" || len(st.Chain) != 1 {
		t.Fatalf("good: %+v", st)
	}
	// Stored with bare LF line endings.
	lf := strings.ReplaceAll(multipartSigned("ana@x.example", inner, sig), "\r\n", "\n")
	if st := c.Check(strings.NewReader(lf)); !st.Verified {
		t.Fatalf("LF: %+v", st)
	}
	tampered := strings.Replace(multipartSigned("ana@x.example", inner, sig), "Friday", "Monday", 1)
	if st := c.Check(strings.NewReader(tampered)); st.Verified || st.Problem != "the message was changed after it was signed" || st.Chain != nil {
		t.Fatalf("tampered: %+v", st)
	}
	if st := c.Check(strings.NewReader(multipartSigned("eve@x.example", inner, sig))); st.Verified || !strings.Contains(st.Problem, "sent from eve@x.example") {
		t.Fatalf("other sender: %+v", st)
	}
	if st := (&Checker{Roots: x509.NewCertPool()}).Check(strings.NewReader(multipartSigned("ana@x.example", inner, sig))); st.Verified ||
		!strings.Contains(st.Problem, "not from an authority") || len(st.Chain) != 1 {
		t.Fatalf("untrusted: %+v", st)
	}
	later := &Checker{Roots: p.roots, Now: func() time.Time { return time.Now().Add(72 * time.Hour) }}
	if st := later.Check(strings.NewReader(multipartSigned("ana@x.example", inner, sig))); !st.Verified {
		// Checked at the signing time, so a later expiry does not matter.
		t.Fatalf("after expiry: %+v", st)
	}

	// Opaque signed: the content comes back to be shown.
	opaque := "From: ana@x.example\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\n\r\n" + wrap64(p.sign(t, inner, false))
	if st := c.Check(strings.NewReader(opaque)); !st.Verified || string(st.Content) != inner {
		t.Fatalf("opaque: %+v", st)
	}

	enc := "From: ana@x.example\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n\r\nxx\r\n"
	if st := c.Check(strings.NewReader(enc)); !st.Encrypted || st.Signed {
		t.Fatalf("encrypted: %+v", st)
	}
	if st := c.Check(strings.NewReader("From: a@b.example\r\nContent-Type: text/plain\r\n\r\nhi\r\n")); st.Signed || st.Encrypted {
		t.Fatalf("plain: %+v", st)
	}
}

func TestVerifyUsage(t *testing.T) {
	p := newPKI(t, "ana@x.example", x509.ExtKeyUsageServerAuth)
	if err := (&Checker{Roots: p.roots}).Verify([]*x509.Certificate{p.leaf}); err == nil || !strings.Contains(err.Error(), "not for email") {
		t.Fatalf("server cert: %v", err)
	}
	if !Covers(p.leaf, "ANA@x.example") || Email(p.leaf) != "ana@x.example" {
		t.Fatal("email")
	}
}

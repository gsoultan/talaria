// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/smime"
)

// testPKI issues an S/MIME certificate for email from a fresh CA.
func testPKI(t *testing.T, email string) (*x509.CertPool, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: email}, EmailAddresses: []string{email},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, leaf, key
}

func wrapB64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	return out.String() + s + "\r\n"
}

func TestSMIME(t *testing.T) {
	const ana = "ana@northwind.example"
	roots, leaf, key := testPKI(t, ana)
	e := setup(t, func(d *Deps) { d.SMIME = &smime.Checker{Roots: roots} })
	e.login()

	// Publish the own certificate; then it is found for encrypting.
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	var certs domain.Certificates
	if st, code := e.call("POST", "/api/v1/certificates", domain.ImportCertificate{Data: pemText, Own: true}, &certs); st != 201 || len(certs.Certificates) != 1 {
		t.Fatalf("import: %d %s %+v", st, code, certs)
	}
	if c := certs.Certificates[0]; c.Email != ana || c.Source != "own" || c.Problem != "" {
		t.Fatalf("imported: %+v", c)
	}
	if st, code := e.call("POST", "/api/v1/certificates", domain.ImportCertificate{Data: "not a certificate"}, nil); st != 400 {
		t.Fatalf("bad import: %d %s", st, code)
	}
	var found domain.FoundCertificates
	if st, _ := e.call("POST", "/api/v1/certificates/find", domain.FindCertificates{Emails: []string{ana, "nobody@else.example"}}, &found); st >= 300 ||
		len(found.Certificates) != 1 || len(found.Missing) != 1 || found.Missing[0] != "nobody@else.example" {
		t.Fatalf("find: %d %+v", st, found)
	}

	// Sign the prepared body as the webmail would, and send it to ana.
	msg := domain.Compose{From: ana, To: []string{ana}, Subject: "signed", TextBody: "hello, signed"}
	var ent domain.SMIMEEntity
	if st, code := e.call("POST", "/api/v1/messages/smime/prepare", domain.PrepareSMIME{Message: msg}, &ent); st >= 300 || !strings.Contains(ent.Entity, "hello, signed") {
		t.Fatalf("prepare: %d %s %q", st, code, ent.Entity)
	}
	sd, err := pkcs7.NewSignedData([]byte(ent.Entity))
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(leaf, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	signed := "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\n" + ent.Entity + "\r\n--b1\r\nContent-Type: application/pkcs7-signature; name=smime.p7s\r\nContent-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=smime.p7s\r\n\r\n" + wrapB64(sig) + "--b1--\r\n"
	if st, code := e.call("POST", "/api/v1/messages/smime/send", domain.SendSMIME{Message: msg, Entity: "Content-Type: text/plain\r\n\r\nplain"}, nil); st != 400 {
		t.Fatalf("unsigned entity: %d %s", st, code)
	}
	if st, code := e.call("POST", "/api/v1/messages/smime/send", domain.SendSMIME{Message: msg, Entity: signed}, nil); st >= 300 {
		t.Fatalf("send: %d %s", st, code)
	}

	var boxes domain.Mailboxes
	e.call("GET", "/api/v1/mailboxes", nil, &boxes)
	var inbox int64
	for _, b := range boxes.Mailboxes {
		if b.SpecialUse == `\Inbox` {
			inbox = b.ID
		}
	}
	var page domain.MessagePage
	e.call("GET", fmt.Sprintf("/api/v1/mailboxes/%d/messages?limit=10", inbox), nil, &page)
	if len(page.Messages) != 1 {
		t.Fatalf("inbox: %+v", page)
	}
	var got domain.Message
	if st, _ := e.call("GET", fmt.Sprintf("/api/v1/messages/%d", page.Messages[0].ID), nil, &got); st != 200 {
		t.Fatalf("get: %d", st)
	}
	d := got.Message
	if d.SMIME == nil || !d.SMIME.Signed || !d.SMIME.Verified || d.SMIME.Signer != ana || d.SMIME.Encrypted {
		t.Fatalf("status: %+v", d.SMIME)
	}
	if !strings.Contains(d.TextBody, "hello, signed") {
		t.Fatalf("body: %q", d.TextBody)
	}
	for _, a := range d.Attachments {
		if strings.HasSuffix(a.Filename, ".p7s") {
			t.Fatalf("signature shown as attachment: %+v", a)
		}
	}

	// The browser's check of a decrypted message's signer.
	var chk domain.CertificateCheck
	chain := []string{base64.StdEncoding.EncodeToString(leaf.Raw)}
	if st, _ := e.call("POST", "/api/v1/certificates/check", domain.CheckCertificates{Chain: chain, From: ana}, &chk); st >= 300 || !chk.Trusted {
		t.Fatalf("check: %d %+v", st, chk)
	}
	if e.call("POST", "/api/v1/certificates/check", domain.CheckCertificates{Chain: chain, From: "mallory@northwind.example"}, &chk); chk.Trusted || chk.Problem == "" {
		t.Fatalf("check other sender: %+v", chk)
	}

	if st, _ := e.call("DELETE", fmt.Sprintf("/api/v1/certificates/%d", certs.Certificates[0].ID), nil, nil); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	e.call("GET", "/api/v1/certificates", nil, &certs)
	for _, c := range certs.Certificates {
		if c.Source == "own" {
			t.Fatalf("own certificate kept: %+v", certs)
		}
	}
}

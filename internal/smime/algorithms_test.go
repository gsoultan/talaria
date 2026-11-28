// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package smime

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Signatures made by OpenSSL with every common key type and form: RSA
// (PKCS #1 v1.5 and PSS), ECDSA on the NIST curves, signers named
// by subject key identifier, opaque and streamed (BER) messages.
func TestCheckAlgorithms(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) []byte {
		cmd := exec.Command("openssl", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	os.WriteFile(filepath.Join(dir, "ext.cnf"), []byte("subjectAltName=email:ana@x.example\nextendedKeyUsage=emailProtection\nkeyUsage=digitalSignature\nsubjectKeyIdentifier=hash\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "msg.txt"), []byte("Content-Type: text/plain\r\n\r\nPay the invoice by Friday.\r\n"), 0o600)
	run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Test CA")
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	b, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	c := &Checker{Roots: roots}

	keys := map[string][]string{
		"rsa":  {"-newkey", "rsa:2048"},
		"p256": {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"},
		"p384": {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"},
		"p521": {"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-521"},
	}
	for name, args := range keys {
		run(append([]string{"req"}, append(args, "-nodes", "-keyout", name+".key", "-out", name+".csr", "-subj", "/CN=Ana")...)...)
		run("x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name+".pem", "-days", "2", "-extfile", "ext.cnf")
	}
	cases := []struct {
		name string
		key  string
		args []string
	}{
		{"rsa sha256", "rsa", []string{"-md", "sha256"}},
		{"rsa sha1", "rsa", []string{"-md", "sha1"}},
		{"rsa pss", "rsa", []string{"-md", "sha256", "-keyopt", "rsa_padding_mode:pss"}},
		{"p256", "p256", []string{"-md", "sha256"}},
		{"p384", "p384", []string{"-md", "sha384"}},
		{"p521", "p521", []string{"-md", "sha512"}},
		{"subject key id", "p256", []string{"-keyid"}},
		{"opaque", "rsa", []string{"-nodetach"}},
		{"opaque streamed", "p384", []string{"-nodetach", "-stream"}},
		{"detached streamed", "rsa", []string{"-stream"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := run(append([]string{"cms", "-sign", "-in", "msg.txt", "-signer", tc.key + ".pem", "-inkey", tc.key + ".key", "-crlfeol"}, tc.args...)...)
			msg := "From: ana@x.example\r\nTo: b@y.example\r\nSubject: Invoice\r\n" + string(out)
			st := c.Check(strings.NewReader(msg))
			if !st.Signed || !st.Verified || st.Signer != "ana@x.example" {
				t.Fatalf("%+v", st)
			}
			opaque := strings.Contains(strings.Join(tc.args, " "), "-nodetach")
			if opaque != strings.Contains(string(st.Content), "Pay the invoice") {
				t.Fatalf("content: %q", st.Content)
			}
			// A change to the signed text is caught.
			if !opaque {
				bad := strings.Replace(msg, "Pay the invoice by Friday.", "Pay the invoice by Monday.", 1)
				if st := c.Check(strings.NewReader(bad)); st.Verified || st.Problem != "the message was changed after it was signed" {
					t.Fatalf("changed: %+v", st)
				}
			}
		})
	}
}

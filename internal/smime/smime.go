// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package smime checks S/MIME signatures and certificates on the server.
// Private keys never come here: signing, encryption and decryption happen
// in the webmail. The server verifies signatures on mail it serves, checks
// certificate chains against the system's roots, and recognises encrypted
// mail so the webmail can decrypt it.
package smime

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-message/textproto"
	"github.com/smallstep/pkcs7"
)

// Status is what the server can tell about a message's S/MIME.
type Status struct {
	Signed    bool
	Encrypted bool // the webmail must decrypt it
	// Verified: the signature matches and the certificate chains to a
	// trusted root and was valid when signed.
	Verified bool
	Signer   string // the certificate's email address
	Problem  string // why it is not verified
	// Chain is the signer's certificate first, then the others the message
	// carried. Set when the signature itself is intact.
	Chain []*x509.Certificate
	// Content is the signed MIME entity of an opaque signed message, to
	// show in place of the message body.
	Content []byte
}

// Checker verifies certificates against a root pool.
type Checker struct {
	// Roots are the trusted roots; nil uses the system's.
	Roots *x509.CertPool
	// Now is the current time; nil uses time.Now.
	Now func() time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Kind reports from a Content-Type whether a message is signed or
// encrypted S/MIME.
func Kind(contentType string) (signed, encrypted bool) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false, false
	}
	switch mt {
	case "multipart/signed":
		p := strings.ToLower(params["protocol"])
		return p == "application/pkcs7-signature" || p == "application/x-pkcs7-signature", false
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
		switch strings.ToLower(params["smime-type"]) {
		case "signed-data":
			return true, false
		case "enveloped-data", "authenveloped-data", "":
			return false, true
		}
	}
	return false, false
}

// Check reads a whole message and verifies its signature, if any. from is
// the address in the From header; a signature by someone else is a problem.
func (c *Checker) Check(r io.Reader) Status {
	br := bufio.NewReaderSize(r, 32<<10)
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return Status{}
	}
	signed, encrypted := Kind(h.Get("Content-Type"))
	if encrypted {
		return Status{Encrypted: true}
	}
	if !signed {
		return Status{}
	}
	from := ""
	if a, err := mail.ParseAddress(h.Get("From")); err == nil {
		from = strings.ToLower(a.Address)
	}
	body, err := io.ReadAll(io.LimitReader(br, 64<<20))
	if err != nil {
		return Status{Signed: true, Problem: "the message could not be read"}
	}
	mt, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
	var p7 *pkcs7.PKCS7
	var content []byte
	if mt == "multipart/signed" {
		content, sig, err := splitSigned(body, params["boundary"])
		if err != nil {
			return Status{Signed: true, Problem: err.Error()}
		}
		if p7, err = pkcs7.Parse(sig); err != nil {
			return Status{Signed: true, Problem: "the signature could not be read"}
		}
		p7.Content = content
	} else {
		der, err := decodeBody(h, body)
		if err == nil {
			p7, err = pkcs7.Parse(der)
		}
		if err != nil {
			return Status{Signed: true, Problem: "the signed message could not be read"}
		}
		content = p7.Content
	}
	st := c.verify(p7, from)
	if mt != "multipart/signed" {
		st.Content = content
	}
	return st
}

// verify checks the signature and the signer's certificate.
func (c *Checker) verify(p7 *pkcs7.PKCS7, from string) Status {
	st := Status{Signed: true}
	signer := p7.GetOnlySigner()
	if signer == nil {
		st.Problem = "the signature does not name exactly one signer"
		return st
	}
	if err := p7.Verify(); err != nil {
		var dm *pkcs7.MessageDigestMismatchError
		if errors.As(err, &dm) {
			st.Problem = "the message was changed after it was signed"
		} else {
			st.Problem = "the signature is not valid"
		}
		return st
	}
	st.Chain = append([]*x509.Certificate{signer}, slices.DeleteFunc(slices.Clone(p7.Certificates), func(x *x509.Certificate) bool { return x.Equal(signer) })...)
	st.Signer = Email(signer)
	when := c.now()
	var t time.Time
	if p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &t) == nil && t.Before(when) && !t.IsZero() {
		when = t
	}
	if err := c.chain(st.Chain, when); err != nil {
		st.Problem = err.Error()
		return st
	}
	if from != "" && !Covers(signer, from) {
		st.Problem = fmt.Sprintf("signed by %s, but sent from %s", st.Signer, from)
		return st
	}
	st.Verified = true
	return st
}

// Verify checks that a certificate (first) chains, through the others, to
// a trusted root, and may protect email.
func (c *Checker) Verify(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("no certificate")
	}
	return c.chain(chain, c.now())
}

func (c *Checker) chain(chain []*x509.Certificate, at time.Time) error {
	ee := chain[0]
	inter := x509.NewCertPool()
	for _, x := range chain[1:] {
		inter.AddCert(x)
	}
	_, err := ee.Verify(x509.VerifyOptions{Roots: c.Roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}})
	var ua x509.UnknownAuthorityError
	var inv x509.CertificateInvalidError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ua):
		return errors.New("the certificate is not from an authority this server trusts")
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return errors.New("the certificate had expired or was not yet valid")
	case errors.As(err, &inv) && inv.Reason == x509.IncompatibleUsage:
		return errors.New("the certificate is not for email")
	}
	return fmt.Errorf("the certificate could not be verified: %v", err)
}

// splitSigned returns the signed part (its raw bytes, headers included, as
// signed) and the decoded signature of a multipart/signed body.
func splitSigned(body []byte, boundary string) (content, sig []byte, err error) {
	if boundary == "" {
		return nil, nil, errors.New("the signed message has no boundary")
	}
	delim := []byte("--" + boundary)
	var parts [][]byte
	partStart := -1
	for pos := 0; pos < len(body); {
		nl := bytes.IndexByte(body[pos:], '\n')
		lineEnd := len(body)
		if nl >= 0 {
			lineEnd = pos + nl + 1
		}
		line := bytes.TrimRight(body[pos:lineEnd], " \t\r\n")
		if bytes.HasPrefix(line, delim) {
			tail := line[len(delim):]
			if len(tail) == 0 || bytes.Equal(tail, []byte("--")) {
				if partStart >= 0 {
					// The line break before a boundary belongs to the boundary.
					end := pos
					if end > partStart && body[end-1] == '\n' {
						end--
						if end > partStart && body[end-1] == '\r' {
							end--
						}
					}
					parts = append(parts, body[partStart:end])
				}
				if len(tail) == 2 {
					break
				}
				partStart = lineEnd
			}
		}
		pos = lineEnd
	}
	if len(parts) != 2 {
		return nil, nil, errors.New("the signed message is not in two parts")
	}
	hdrEnd, skip := bytes.Index(parts[1], []byte("\r\n\r\n")), 4
	if hdrEnd < 0 {
		hdrEnd, skip = bytes.Index(parts[1], []byte("\n\n")), 2
	}
	if hdrEnd < 0 {
		return nil, nil, errors.New("the signature part could not be read")
	}
	sh, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(parts[1][:hdrEnd+skip])))
	if err != nil {
		return nil, nil, errors.New("the signature part could not be read")
	}
	if sig, err = decodeBody(sh, parts[1][hdrEnd+skip:]); err != nil {
		return nil, nil, err
	}
	// Signers canonicalise to CRLF; a message stored with bare LF is
	// restored before checking.
	if !bytes.Contains(parts[0], []byte("\r\n")) {
		parts[0] = bytes.ReplaceAll(parts[0], []byte("\n"), []byte("\r\n"))
	}
	return parts[0], sig, nil
}

func decodeBody(h textproto.Header, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, body)
		out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, err := base64.StdEncoding.Decode(out, clean)
		if err != nil {
			return nil, errors.New("the signature is not valid base64")
		}
		return out[:n], nil
	case "", "binary", "7bit", "8bit":
		return body, nil
	}
	return nil, errors.New("the signature uses an unknown encoding")
}

var oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Email returns a certificate's first email address, from its alternative
// names or, for older certificates, its subject.
func Email(c *x509.Certificate) string {
	if a := Emails(c); len(a) > 0 {
		return a[0]
	}
	return ""
}

// Emails lists a certificate's email addresses, lower case.
func Emails(c *x509.Certificate) []string {
	var out []string
	for _, e := range c.EmailAddresses {
		out = append(out, strings.ToLower(e))
	}
	for _, n := range c.Subject.Names {
		if n.Type.Equal(oidEmail) {
			if s, ok := n.Value.(string); ok && !slices.Contains(out, strings.ToLower(s)) {
				out = append(out, strings.ToLower(s))
			}
		}
	}
	return out
}

// Covers reports whether the certificate is for the address.
func Covers(c *x509.Certificate, address string) bool {
	return slices.Contains(Emails(c), strings.ToLower(address))
}

// Fingerprint is the certificate's SHA-256.
func Fingerprint(c *x509.Certificate) []byte {
	s := sha256.Sum256(c.Raw)
	return s[:]
}

// ParseCertificates reads certificates in PEM or DER.
func ParseCertificates(b []byte) ([]*x509.Certificate, error) {
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte("-----BEGIN")) {
		var out []*x509.Certificate
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(blk.Bytes)
				if err != nil {
					return nil, err
				}
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no certificate found")
		}
		return out, nil
	}
	return x509.ParseCertificates(b)
}

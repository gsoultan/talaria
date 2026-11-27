// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

// SMIMEStatus is what the server found about a message's S/MIME.
type SMIMEStatus struct {
	Signed bool `json:"signed"`
	// Encrypted means the webmail must decrypt the message with the key in
	// the browser.
	Encrypted bool `json:"encrypted"`
	// Verified: the signature matches and the certificate is trusted, valid
	// and for the sender's address.
	Verified bool   `json:"verified"`
	Signer   string `json:"signer"`
	Problem  string `json:"problem"`
}

// Certificate is an S/MIME certificate the user knows, for one address.
type Certificate struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   int64  `json:"notBefore"`
	NotAfter    int64  `json:"notAfter"`
	Fingerprint string `json:"fingerprint"` // SHA-256, hex
	// Source is own, imported (by the user) or harvested (from signed mail).
	Source string `json:"source"`
	// Problem says why the server does not trust it; empty when it does.
	Problem string `json:"problem"`
	// DER is the certificate, base64.
	DER string `json:"der"`
}

// ListCertificates asks for the user's certificates.
type ListCertificates struct{}

// Certificates lists certificates.
type Certificates struct {
	Certificates []Certificate `json:"certificates"`
}

// ImportCertificate adds certificates: PEM text, or DER in base64. Own
// publishes the user's own certificate (never the private key) so
// colleagues can encrypt to them.
type ImportCertificate struct {
	Data string `json:"data"`
	Own  bool   `json:"own,omitzero"`
}

// DeleteCertificate removes one.
type DeleteCertificate struct {
	ID int64 `json:"-" path:"id"`
}

// FindCertificates looks up the certificate to encrypt to for each
// address: the user's own store first, then what colleagues published.
type FindCertificates struct {
	Emails []string `json:"emails"`
}

// FoundCertificates has the best certificate for each address found, and
// the addresses with none.
type FoundCertificates struct {
	Certificates []Certificate `json:"certificates"`
	Missing      []string      `json:"missing"`
}

// CheckCertificates asks whether a signer's certificate (first, then the
// rest of its chain, base64 DER) is trusted. The webmail sends it after
// it checked the signature inside a message it decrypted; a trusted
// certificate for From is remembered for replies.
type CheckCertificates struct {
	Chain []string `json:"chain"`
	From  string   `json:"from,omitzero"`
}

// CertificateCheck is the verdict.
type CertificateCheck struct {
	Trusted bool   `json:"trusted"`
	Email   string `json:"email"`
	Problem string `json:"problem"`
}

// PrepareSMIME renders the body of a message for the webmail to sign or
// encrypt.
type PrepareSMIME struct {
	Message Compose `json:"message"`
}

// SMIMEEntity is a MIME entity: Content-* header fields, a blank line, the
// body, with CRLF line endings.
type SMIMEEntity struct {
	Entity string `json:"entity"`
}

// SendSMIME sends a message whose body the webmail signed or encrypted.
// Message gives the headers and recipients; its text and attachments are
// checked by the data loss prevention policies but not sent.
type SendSMIME struct {
	Message          Compose `json:"message"`
	Entity           string  `json:"entity"`
	ConfirmSensitive bool    `json:"confirmSensitive,omitzero"`
}

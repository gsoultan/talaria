// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/smime"
	"github.com/gsoultan/talaria/internal/store"
)

func (s *Mail) checker() *smime.Checker {
	if s.SMIME != nil {
		return s.SMIME
	}
	return &smime.Checker{}
}

// certOf describes a stored certificate. The stored DER is the chain, leaf
// first; the client gets the leaf.
func (s *Mail) certOf(c store.Certificate) domain.Certificate {
	out := domain.Certificate{ID: c.ID, Email: c.Email, Subject: c.Subject, Issuer: c.Issuer, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Fingerprint: hex.EncodeToString(c.Fingerprint), Source: c.Source}
	chain, err := x509.ParseCertificates(c.DER)
	if err != nil || len(chain) == 0 {
		out.Problem = "the certificate could not be read"
		return out
	}
	out.DER = base64.StdEncoding.EncodeToString(chain[0].Raw)
	if err := s.checker().Verify(chain); err != nil {
		out.Problem = err.Error()
	}
	return out
}

// remember stores a certificate chain for each of the leaf's addresses
// that keep allows.
func (s *Mail) remember(ctx context.Context, u store.User, chain []*x509.Certificate, source string, keep func(email string) bool) (int, error) {
	leaf := chain[0]
	var der []byte
	for _, c := range chain {
		der = append(der, c.Raw...)
	}
	n := 0
	for _, e := range smime.Emails(leaf) {
		if !keep(e) {
			continue
		}
		err := s.Store.SaveCertificate(ctx, store.Certificate{UserID: u.ID, Email: e, DER: der, Fingerprint: smime.Fingerprint(leaf),
			Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix(), Source: source})
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ListCertificates returns the user's certificates.
func (s *Mail) ListCertificates(ctx context.Context, _ domain.ListCertificates) (domain.Certificates, error) {
	cs, err := s.Store.Certificates(ctx, userOf(ctx).ID)
	if err != nil {
		return domain.Certificates{}, storeErr(err)
	}
	out := domain.Certificates{Certificates: make([]domain.Certificate, 0, len(cs))}
	for _, c := range cs {
		out.Certificates = append(out.Certificates, s.certOf(c))
	}
	return out, nil
}

func parseChain(data string) ([]*x509.Certificate, error) {
	data = strings.TrimSpace(data)
	b := []byte(data)
	if !strings.HasPrefix(data, "-----BEGIN") {
		// One base64 blob, maybe wrapped; or one certificate per line.
		var err error
		if b, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), "")); err != nil {
			b = nil
			for _, f := range strings.Fields(data) {
				d, err := base64.StdEncoding.DecodeString(f)
				if err != nil {
					return nil, errors.New("not a certificate in PEM or base64 DER")
				}
				b = append(b, d...)
			}
		}
	}
	chain, err := smime.ParseCertificates(b)
	if err != nil || len(chain) == 0 {
		return nil, errors.New("not a certificate in PEM or base64 DER")
	}
	if len(chain) > 10 {
		chain = chain[:10]
	}
	return chain, nil
}

// ImportCertificate stores certificates the user adds: a contact's, or
// their own public certificate.
func (s *Mail) ImportCertificate(ctx context.Context, in domain.ImportCertificate) (domain.Certificates, error) {
	u := userOf(ctx)
	if len(in.Data) > 256<<10 {
		return domain.Certificates{}, badField("data", errors.New("that is too large for a certificate"))
	}
	chain, err := parseChain(in.Data)
	if err != nil {
		return domain.Certificates{}, badField("data", err)
	}
	if len(smime.Emails(chain[0])) == 0 {
		return domain.Certificates{}, badField("data", errors.New("the certificate names no email address"))
	}
	source, keep := store.CertImported, func(string) bool { return true }
	if in.Own {
		source, keep = store.CertOwn, func(e string) bool { return s.Store.CanSendAs(ctx, u, e) }
	}
	n, err := s.remember(ctx, u, chain, source, keep)
	if err != nil {
		return domain.Certificates{}, storeErr(err)
	}
	if n == 0 {
		return domain.Certificates{}, badField("data", errors.New("the certificate is not for an address you send from"))
	}
	return s.ListCertificates(ctx, domain.ListCertificates{})
}

// DeleteCertificate removes one of the user's certificates.
func (s *Mail) DeleteCertificate(ctx context.Context, in domain.DeleteCertificate) (domain.Done, error) {
	return domain.Done{}, storeErr(s.Store.DeleteCertificate(ctx, userOf(ctx).ID, in.ID))
}

// FindCertificates picks, for each address, the newest certificate that is
// valid now, preferring trusted ones.
func (s *Mail) FindCertificates(ctx context.Context, in domain.FindCertificates) (domain.FoundCertificates, error) {
	u := userOf(ctx)
	if len(in.Emails) > 500 {
		return domain.FoundCertificates{}, badField("emails", errors.New("too many addresses"))
	}
	var emails []string
	for _, e := range in.Emails {
		emails = append(emails, strings.ToLower(strings.TrimSpace(e)))
	}
	cs, err := s.Store.CertificatesFor(ctx, u, emails)
	if err != nil {
		return domain.FoundCertificates{}, storeErr(err)
	}
	now := time.Now().Unix()
	best := map[string]domain.Certificate{}
	for _, c := range cs {
		if c.NotAfter < now || c.NotBefore > now {
			continue
		}
		d := s.certOf(c)
		if d.DER == "" {
			continue
		}
		cur, ok := best[c.Email]
		if !ok || (cur.Problem != "" && d.Problem == "") {
			best[c.Email] = d
		}
	}
	out := domain.FoundCertificates{Certificates: []domain.Certificate{}, Missing: []string{}}
	for _, e := range emails {
		if c, ok := best[e]; ok {
			out.Certificates = append(out.Certificates, c)
			delete(best, e)
		} else if !strings.Contains(strings.Join(out.Missing, ","), e) {
			out.Missing = append(out.Missing, e)
		}
	}
	return out, nil
}

// CheckCertificates verifies a signer's chain the webmail found inside a
// decrypted message, and remembers a trusted one for the sender.
func (s *Mail) CheckCertificates(ctx context.Context, in domain.CheckCertificates) (domain.CertificateCheck, error) {
	if len(in.Chain) == 0 || len(in.Chain) > 10 {
		return domain.CertificateCheck{}, badField("chain", errors.New("send the signer's certificate first, then its chain"))
	}
	var chain []*x509.Certificate
	for _, c := range in.Chain {
		der, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return domain.CertificateCheck{}, badField("chain", errors.New("not base64"))
		}
		x, err := x509.ParseCertificate(der)
		if err != nil {
			return domain.CertificateCheck{}, badField("chain", errors.New("not a certificate"))
		}
		chain = append(chain, x)
	}
	out := domain.CertificateCheck{Email: smime.Email(chain[0])}
	if err := s.checker().Verify(chain); err != nil {
		out.Problem = err.Error()
		return out, nil
	}
	from := strings.ToLower(strings.TrimSpace(in.From))
	if from != "" && !smime.Covers(chain[0], from) {
		out.Problem = "signed by " + out.Email + ", but sent from " + from
		return out, nil
	}
	out.Trusted = true
	if from != "" {
		s.remember(ctx, userOf(ctx), chain, store.CertHarvested, func(e string) bool { return e == from })
	}
	return out, nil
}

// PrepareSMIME renders the body the webmail will sign or encrypt.
func (s *Mail) PrepareSMIME(ctx context.Context, in domain.PrepareSMIME) (domain.SMIMEEntity, error) {
	c, err := s.build(ctx, userOf(ctx), in.Message, false)
	if err != nil {
		return domain.SMIMEEntity{}, err
	}
	var buf bytes.Buffer
	if err := c.WriteEntity(&buf); err != nil {
		return domain.SMIMEEntity{}, internal(err)
	}
	return domain.SMIMEEntity{Entity: buf.String()}, nil
}

// SendSMIME sends a message whose body the webmail signed or encrypted.
// Policies read a signed body as it is; for an encrypted one they read the
// message as composed, since they cannot read what is sent.
func (s *Mail) SendSMIME(ctx context.Context, in domain.SendSMIME) (domain.Sent, error) {
	u := userOf(ctx)
	if s.MaxSize > 0 && int64(len(in.Entity)) > s.MaxSize {
		return domain.Sent{}, kakarot.E(kakarot.CodeInvalid, "the message is too large", nil)
	}
	ct := ""
	if i := strings.Index(in.Entity, "\r\n\r\n"); i > 0 {
		for _, line := range strings.Split(strings.ReplaceAll(in.Entity[:i], "\r\n\t", " "), "\r\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
				ct = strings.TrimSpace(v)
			}
		}
	}
	signed, encrypted := smime.Kind(ct)
	if !signed && !encrypted {
		return domain.Sent{}, badField("entity", errors.New("the body is not signed or encrypted S/MIME"))
	}
	c, err := s.build(ctx, u, in.Message, false)
	if err != nil {
		return domain.Sent{}, err
	}
	var plain []byte
	if encrypted {
		var buf bytes.Buffer
		if err := c.Write(&buf); err != nil {
			return domain.Sent{}, internal(err)
		}
		plain = buf.Bytes()
	}
	c.Entity = []byte(in.Entity)
	return s.send(ctx, u, c, in.Message.DraftID, in.ConfirmSensitive, plain)
}

// smimeStatus checks a message's signature for the reader, remembering a
// trusted signer's certificate. It returns the signed content of an
// opaque signed message, to show in place of the body.
func (s *Mail) smimeStatus(ctx context.Context, u store.User, open func() ([]byte, error)) (*domain.SMIMEStatus, []byte) {
	raw, err := open()
	if err != nil {
		return nil, nil
	}
	st := s.checker().Check(bytes.NewReader(raw))
	if !st.Signed && !st.Encrypted {
		return nil, nil
	}
	if st.Verified {
		from := st.Signer
		s.remember(ctx, u, st.Chain, store.CertHarvested, func(e string) bool { return e == from })
	}
	return &domain.SMIMEStatus{Signed: st.Signed, Encrypted: st.Encrypted, Verified: st.Verified, Signer: st.Signer, Problem: st.Problem}, st.Content
}

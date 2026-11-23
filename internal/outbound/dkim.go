// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package outbound accepts mail from local users, signs it with DKIM, and
// delivers it: locally, through a relay (smarthost), or directly to MX hosts.
package outbound

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/gsoultan/talaria/internal/store"
)

// Keys loads and caches DKIM keys, creating one the first time a domain
// sends (or when the admin asks for its DNS records).
type Keys struct {
	Store *store.Store
	mu    sync.Mutex
	cache map[string]crypto.Signer
}

// Selector names new keys by month, so a rotated key gets a new DNS name.
func newSelector(t time.Time) string { return "tal" + t.Format("200601") }

// Ensure returns the domain's key, creating an RSA-2048 key if it has none.
// RSA is used because Ed25519 DKIM is still not verified by every receiver.
func (k *Keys) Ensure(ctx context.Context, domain string) (store.DKIMKey, crypto.Signer, error) {
	key, err := k.Store.DKIMKeyFor(ctx, domain)
	if errors.Is(err, store.ErrNotFound) {
		d, err := k.Store.DomainByName(ctx, domain)
		if err != nil {
			return key, nil, err
		}
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return key, nil, err
		}
		der, _ := x509.MarshalPKCS8PrivateKey(priv)
		key = store.DKIMKey{DomainID: d.ID, Domain: d.Name, Selector: newSelector(time.Now()), Algorithm: "rsa", PrivateKey: der}
		if err := k.Store.SetDKIMKey(ctx, key); err != nil {
			return key, nil, err
		}
		k.forget(d.Name)
		return k.Ensure(ctx, domain)
	}
	if err != nil {
		return key, nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cache == nil {
		k.cache = map[string]crypto.Signer{}
	}
	if s, ok := k.cache[key.Domain+"/"+key.Selector]; ok {
		return key, s, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(key.PrivateKey)
	if err != nil {
		return key, nil, err
	}
	s, ok := parsed.(crypto.Signer)
	if !ok {
		return key, nil, errors.New("dkim key is not a signer")
	}
	k.cache[key.Domain+"/"+key.Selector] = s
	return key, s, nil
}

func (k *Keys) forget(domain string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for name := range k.cache {
		if len(name) > len(domain) && name[:len(domain)+1] == domain+"/" {
			delete(k.cache, name)
		}
	}
}

// DNSRecord returns the TXT record value publishing the domain's key.
func (k *Keys) DNSRecord(ctx context.Context, domain string) (selector, value string, err error) {
	key, signer, err := k.Ensure(ctx, domain)
	if err != nil {
		return "", "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", "", err
	}
	return key.Selector, fmt.Sprintf("v=DKIM1; k=%s; p=%s", key.Algorithm, base64.StdEncoding.EncodeToString(pub)), nil
}

// signedHeaders are covered by the signature; From is required.
var signedHeaders = []string{"From", "Reply-To", "Subject", "Date", "To", "Cc", "Message-ID", "In-Reply-To", "References",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding", "List-Unsubscribe"}

// Sign returns a DKIM-Signature header line (with CRLF) for r.
func (k *Keys) Sign(ctx context.Context, domain string, r io.Reader) (string, error) {
	key, signer, err := k.Ensure(ctx, domain)
	if err != nil {
		return "", err
	}
	s, err := dkim.NewSigner(&dkim.SignOptions{
		Domain: key.Domain, Selector: key.Selector, Signer: signer, Hash: crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed, BodyCanonicalization: dkim.CanonicalizationRelaxed,
		HeaderKeys: signedHeaders,
	})
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(s, r); err != nil {
		s.Close()
		return "", err
	}
	if err := s.Close(); err != nil {
		return "", err
	}
	return s.Signature(), nil
}

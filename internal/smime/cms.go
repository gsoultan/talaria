// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package smime

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "crypto/sha1" // for signatures made with SHA-1
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// A CMS SignedData reader (RFC 5652) that takes BER as mail apps write it,
// signers named by issuer and serial or by subject key identifier, and RSA
// (PKCS #1 v1.5 and PSS), ECDSA and Ed25519 signatures.

// node is one BER element.
type node struct {
	class, tag  int
	constructed bool
	raw, body   []byte
	children    []node
}

var errBER = errors.New("malformed signature")

func readNode(b []byte, depth int) (node, []byte, error) {
	if depth > 64 || len(b) < 2 {
		return node{}, nil, errBER
	}
	start := b
	n := node{class: int(b[0] >> 6), constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	b = b[1:]
	if n.tag == 0x1f {
		n.tag = 0
		for {
			if len(b) == 0 || n.tag > 1<<20 {
				return node{}, nil, errBER
			}
			c := b[0]
			b = b[1:]
			n.tag = n.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if len(b) == 0 {
		return node{}, nil, errBER
	}
	l := int(b[0])
	b = b[1:]
	indefinite := false
	switch {
	case l == 0x80:
		if !n.constructed {
			return node{}, nil, errBER
		}
		indefinite = true
	case l > 0x80:
		k := l & 0x7f
		if k > 4 || len(b) < k {
			return node{}, nil, errBER
		}
		l = 0
		for _, c := range b[:k] {
			l = l<<8 | int(c)
		}
		b = b[k:]
	}
	if indefinite {
		body := b
		for {
			if len(b) >= 2 && b[0] == 0 && b[1] == 0 {
				n.body = body[:len(body)-len(b)]
				b = b[2:]
				break
			}
			c, rest, err := readNode(b, depth+1)
			if err != nil {
				return node{}, nil, err
			}
			n.children = append(n.children, c)
			b = rest
		}
	} else {
		if l < 0 || len(b) < l {
			return node{}, nil, errBER
		}
		n.body = b[:l]
		b = b[l:]
		if n.constructed {
			for rest := n.body; len(rest) > 0; {
				c, r, err := readNode(rest, depth+1)
				if err != nil {
					return node{}, nil, err
				}
				n.children = append(n.children, c)
				rest = r
			}
		}
	}
	n.raw = start[:len(start)-len(b)]
	return n, b, nil
}

func parseBER(b []byte) (node, error) {
	n, _, err := readNode(b, 0)
	return n, err
}

func (n node) child(i int) (node, error) {
	if i >= len(n.children) {
		return node{}, errBER
	}
	return n.children[i], nil
}

// octets joins the pieces of a (possibly constructed) OCTET STRING.
func (n node) octets() []byte {
	if !n.constructed {
		return n.body
	}
	var out []byte
	for _, c := range n.children {
		out = append(out, c.octets()...)
	}
	return out
}

func (n node) oid() (asn1.ObjectIdentifier, error) {
	var o asn1.ObjectIdentifier
	if n.class != 0 || n.tag != asn1.TagOID {
		return nil, errBER
	}
	_, err := asn1.Unmarshal(n.raw, &o)
	return o, err
}

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidRSA           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidSubjectKeyID  = asn1.ObjectIdentifier{2, 5, 29, 14}
)

var digests = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// Signature algorithms that name their hash.
var rsaSigHash = map[string]crypto.Hash{
	"1.2.840.113549.1.1.5":  crypto.SHA1,
	"1.2.840.113549.1.1.14": crypto.SHA224,
	"1.2.840.113549.1.1.11": crypto.SHA256,
	"1.2.840.113549.1.1.12": crypto.SHA384,
	"1.2.840.113549.1.1.13": crypto.SHA512,
}

var ecdsaSigHash = map[string]crypto.Hash{
	"1.2.840.10045.4.1":   crypto.SHA1,
	"1.2.840.10045.4.3.1": crypto.SHA224,
	"1.2.840.10045.4.3.2": crypto.SHA256,
	"1.2.840.10045.4.3.3": crypto.SHA384,
	"1.2.840.10045.4.3.4": crypto.SHA512,
}

// signature is a SignedData read and checked.
type signature struct {
	content  []byte // the encapsulated content, when embedded
	certs    []*x509.Certificate
	signer   *x509.Certificate
	signedAt time.Time
}

// problem is a reason a signature does not hold, worded for people.
type problem string

func (p problem) Error() string { return string(p) }

const (
	errChanged    = problem("the message was changed after it was signed")
	errInvalid    = problem("the signature is not valid")
	errUnreadable = problem("the signature could not be read")
)

// verifySigned checks a SignedData's only signature over content (or the
// embedded content when content is nil). The signer's certificate is
// returned when the signature itself holds; its chain is not checked here.
func verifySigned(der, content []byte) (signature, error) {
	var out signature
	ci, err := parseBER(der)
	if err != nil || len(ci.children) < 2 {
		return out, errUnreadable
	}
	if o, err := ci.children[0].oid(); err != nil || !o.Equal(oidSignedData) {
		return out, errUnreadable
	}
	sdw := ci.children[1]
	sd, err := sdw.child(0)
	if err != nil || len(sd.children) < 4 {
		return out, errUnreadable
	}
	encap := sd.children[2]
	for _, c := range encap.children {
		if c.class == 2 && c.tag == 0 && len(c.children) > 0 {
			out.content = c.children[0].octets()
		}
	}
	if content == nil {
		content = out.content
	}
	if content == nil {
		return out, problem("the signed content is missing")
	}
	var infos node
	for _, c := range sd.children[3:] {
		switch {
		case c.class == 2 && c.tag == 0:
			for _, cc := range c.children {
				if cc.class == 0 && cc.tag == asn1.TagSequence {
					if cert, err := x509.ParseCertificate(cc.raw); err == nil {
						out.certs = append(out.certs, cert)
					}
				}
			}
		case c.class == 0 && c.tag == asn1.TagSet:
			infos = c
		}
	}
	if len(infos.children) != 1 {
		return out, problem("the signature does not name exactly one signer")
	}
	si := infos.children[0]
	sid, err := si.child(1)
	if err != nil {
		return out, errUnreadable
	}
	out.signer = findSigner(out.certs, sid)
	if out.signer == nil {
		return out, problem("the signer’s certificate is not in the message")
	}
	dalg, err := si.child(2)
	if err != nil {
		return out, errUnreadable
	}
	doid, err := dalg.children[0].oid()
	hash, ok := digests[doid.String()]
	if err != nil || !ok {
		return out, problem("the signature uses an unknown hash")
	}
	i := 3
	var attrs *node
	if i < len(si.children) && si.children[i].class == 2 && si.children[i].tag == 0 {
		attrs = &si.children[i]
		i++
	}
	if i+1 >= len(si.children) {
		return out, errUnreadable
	}
	salg := si.children[i]
	sig := si.children[i+1].octets()
	h := hash.New()
	h.Write(content)
	sum := h.Sum(nil)
	data := content
	if attrs != nil {
		var md []byte
		for _, a := range attrs.children {
			if len(a.children) < 2 || len(a.children[1].children) < 1 {
				continue
			}
			t, err := a.children[0].oid()
			if err != nil {
				continue
			}
			v := a.children[1].children[0]
			switch {
			case t.Equal(oidMessageDigest):
				md = v.octets()
			case t.Equal(oidSigningTime):
				var tm time.Time
				if _, err := asn1.Unmarshal(v.raw, &tm); err == nil {
					out.signedAt = tm
				}
			}
		}
		if md == nil || subtle.ConstantTimeCompare(md, sum) != 1 {
			return out, errChanged
		}
		// The signature covers the attributes as a SET, not as [0].
		data = append([]byte{0x31}, attrs.raw[1:]...)
	}
	if err := checkSig(out.signer, salg, hash, data, sig); err != nil {
		return out, err
	}
	return out, nil
}

func findSigner(certs []*x509.Certificate, sid node) *x509.Certificate {
	for _, c := range certs {
		if sid.class == 0 && sid.tag == asn1.TagSequence && len(sid.children) == 2 {
			var serial *big.Int
			if _, err := asn1.Unmarshal(sid.children[1].raw, &serial); err != nil {
				return nil
			}
			if bytes.Equal(c.RawIssuer, sid.children[0].raw) && c.SerialNumber.Cmp(serial) == 0 {
				return c
			}
		} else if sid.class == 2 && sid.tag == 0 && len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.octets()) {
			return c
		}
	}
	return nil
}

type pssParams struct {
	Hash       asn1.RawValue `asn1:"optional,explicit,tag:0"`
	MGF        asn1.RawValue `asn1:"optional,explicit,tag:1"`
	SaltLength int           `asn1:"optional,explicit,tag:2,default:20"`
}

// checkSig verifies sig over data with the signer's key.
func checkSig(c *x509.Certificate, alg node, digest crypto.Hash, data, sig []byte) error {
	if len(alg.children) == 0 {
		return errUnreadable
	}
	id, err := alg.children[0].oid()
	if err != nil {
		return errUnreadable
	}
	hashed := func(h crypto.Hash) []byte {
		w := h.New()
		w.Write(data)
		return w.Sum(nil)
	}
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		switch {
		case id.Equal(oidRSAPSS):
			p := pssParams{SaltLength: 20}
			h := crypto.SHA1
			if len(alg.children) > 1 {
				if _, err := asn1.Unmarshal(alg.children[1].raw, &p); err != nil {
					return errUnreadable
				}
				if len(p.Hash.Bytes) > 0 {
					var ai struct{ Algorithm asn1.ObjectIdentifier }
					if _, err := asn1.UnmarshalWithParams(p.Hash.Bytes, &ai, ""); err != nil {
						return errUnreadable
					}
					var ok bool
					if h, ok = digests[ai.Algorithm.String()]; !ok {
						return problem("the signature uses an unknown hash")
					}
				}
			}
			if rsa.VerifyPSS(pub, h, hashed(h), sig, &rsa.PSSOptions{SaltLength: p.SaltLength, Hash: h}) != nil {
				return errInvalid
			}
			return nil
		case id.Equal(oidRSA) || rsaSigHash[id.String()] != 0:
			h := digest
			if rh := rsaSigHash[id.String()]; rh != 0 {
				h = rh
			}
			if rsa.VerifyPKCS1v15(pub, h, hashed(h), sig) != nil {
				return errInvalid
			}
			return nil
		}
	case *ecdsa.PublicKey:
		h := ecdsaSigHash[id.String()]
		if h == 0 && id.Equal(oidECPublicKey) {
			h = digest
		}
		if h == 0 {
			break
		}
		if !ecdsa.VerifyASN1(pub, hashed(h), sig) {
			return errInvalid
		}
		return nil
	case ed25519.PublicKey:
		if !id.Equal(oidEd25519) {
			break
		}
		if !ed25519.Verify(pub, data, sig) {
			return errInvalid
		}
		return nil
	default:
		return problem("the signer’s key type is not supported")
	}
	return problem("the signature uses an unknown algorithm")
}

// Package tagtest is a software p256tag identity for tests. Real tag keys live
// in hardware (TPM, YubiKey, Secure Enclave); this one is derived from a seed
// so tests can decrypt what age wraps to an age1tag1 recipient.
package tagtest

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/tag"
	"filippo.io/hpke"
	"filippo.io/nistec"
)

// Identity is a P-256 tag identity. Never use it outside tests.
type Identity struct {
	k hpke.PrivateKey
}

var _ age.Identity = &Identity{}

// New derives an identity from seed.
func New(seed string) *Identity {
	k, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair([]byte(seed))
	if err != nil {
		panic(fmt.Sprintf("derive key: %v", err))
	}
	return &Identity{k: k}
}

// Recipient is the age1tag1 recipient for this identity.
func (i *Identity) Recipient() *tag.Recipient {
	p, err := nistec.NewP256Point().SetBytes(i.k.PublicKey().Bytes())
	if err != nil {
		panic(fmt.Sprintf("public key: %v", err))
	}
	r, err := tag.NewClassicRecipient(p.BytesCompressed())
	if err != nil {
		panic(fmt.Sprintf("recipient: %v", err))
	}
	return r
}

// Unwrap follows age's p256tag stanza spec (age-encryption.org/p256tag).
func (i *Identity) Unwrap(ss []*age.Stanza) ([]byte, error) {
	for _, s := range ss {
		if s.Type != "p256tag" || len(s.Args) != 2 || len(s.Body) != 32 {
			continue
		}
		tagArg, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		if err != nil || len(tagArg) != 4 {
			continue
		}
		enc, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
		if err != nil || len(enc) != 65 {
			continue
		}
		want, err := i.Recipient().Tag(enc)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(tagArg, want[:4]) != 1 {
			continue
		}
		r, err := hpke.NewRecipient(enc, i.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/p256tag"))
		if err != nil {
			return nil, err
		}
		return r.Open(nil, s.Body)
	}
	return nil, age.ErrIncorrectIdentity
}

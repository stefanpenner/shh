// Package shhcore is the iOS entry to the vault. It does not read the keychain.
package shhcore

import (
	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/encfile"
)

// Vault is one opened .env.enc. Close wipes the data key.
type Vault struct {
	session   *encfile.Session
	recipient string
	names     []string
	parties   []encfile.Party
}

// PublicRecipient is the age recipient for an identity. It is not a secret.
func PublicRecipient(identity string) (string, error) {
	if identity == "" {
		return "", errors.New("identity is empty")
	}
	return crypto.PublicKeyFrom(identity)
}

// Open checks the file MAC. It does not decrypt secret values.
func Open(identity string, file []byte) (*Vault, error) {
	pub, err := PublicRecipient(identity)
	if err != nil {
		return nil, err
	}
	session, err := encfile.Open(file, identity)
	if err != nil {
		return nil, err
	}
	return &Vault{
		session:   session,
		recipient: pub,
		names:     session.Names(),
		parties:   session.Recipients(),
	}, nil
}

// Recipient is the age recipient that opened this vault.
func (v *Vault) Recipient() string {
	if v == nil {
		return ""
	}
	return v.recipient
}

// Count is the number of secret names.
func (v *Vault) Count() int {
	if v == nil {
		return 0
	}
	return len(v.names)
}

// Name returns one secret name. The index starts at 0.
func (v *Vault) Name(index int) (string, error) {
	if v == nil || v.session == nil {
		return "", errors.New("vault is closed")
	}
	if index < 0 || index >= len(v.names) {
		return "", errors.New("no such secret")
	}
	return v.names[index], nil
}

// RecipientCount is the number of public recipients on the file.
func (v *Vault) RecipientCount() int {
	if v == nil || v.session == nil {
		return 0
	}
	return len(v.parties)
}

// RecipientName is the label at index. The index starts at 0. Names are sorted.
func (v *Vault) RecipientName(index int) (string, error) {
	party, err := v.party(index)
	if err != nil {
		return "", err
	}
	return party.Name, nil
}

// RecipientKey is the age recipient at index. It is not a secret.
func (v *Vault) RecipientKey(index int) (string, error) {
	party, err := v.party(index)
	if err != nil {
		return "", err
	}
	return party.Key, nil
}

func (v *Vault) party(index int) (encfile.Party, error) {
	if v == nil || v.session == nil {
		return encfile.Party{}, errors.New("vault is closed")
	}
	if index < 0 || index >= len(v.parties) {
		return encfile.Party{}, errors.New("no such recipient")
	}
	return v.parties[index], nil
}

// Secret decrypts one value by name.
func (v *Vault) Secret(name string) (string, error) {
	if v == nil || v.session == nil {
		return "", errors.New("vault is closed")
	}
	return v.session.Secret(name)
}

// Close wipes the data key. A second call does nothing.
func (v *Vault) Close() {
	if v == nil || v.session == nil {
		return
	}
	v.session.Close()
	v.session = nil
	v.names = nil
	v.parties = nil
}

// Command age-plugin-shhtest is a minimal age plugin used ONLY by shh's tests to
// exercise the plugin code path end to end without real hardware. It "wraps" the
// file key with a trivial XOR over key material carried in the recipient/identity
// encoding. This is NOT secure and must never be used for real secrets — it
// exists so the test suite can prove shh drives the age plugin protocol.
package main

import (
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

type xorRecipient struct{ key []byte }

func (r *xorRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	body := make([]byte, len(fileKey))
	for i := range fileKey {
		body[i] = fileKey[i] ^ r.key[i%len(r.key)]
	}
	return []*age.Stanza{{Type: "shhtest", Body: body}}, nil
}

type xorIdentity struct{ key []byte }

func (i *xorIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type != "shhtest" {
			continue
		}
		out := make([]byte, len(s.Body))
		for j := range s.Body {
			out[j] = s.Body[j] ^ i.key[j%len(i.key)]
		}
		return out, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func main() {
	p, err := plugin.New("shhtest")
	if err != nil {
		os.Exit(1)
	}
	p.HandleRecipient(func(data []byte) (age.Recipient, error) { return &xorRecipient{key: data}, nil })
	p.HandleIdentity(func(data []byte) (age.Identity, error) { return &xorIdentity{key: data}, nil })
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) { return &xorRecipient{key: data}, nil })
	os.Exit(p.Main())
}

// Package vault opens a shh .env.enc from Go with an age.Identity the caller
// already holds. It is for programs that embed shh's format, such as a node
// agent that unwraps with a TPM key in process. It never runs a plugin binary
// and never writes plaintext anywhere; values are decrypted one at a time.
//
// Writing a vault stays in the shh CLI. Add the program's recipient with
// `shh users add --name <name> --key <age1…>` and it can read the file.
package vault

import (
	"filippo.io/age"
	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
)

// Vault is one opened .env.enc. The file MAC was checked on Open. Close wipes
// the data key.
type Vault struct {
	session *encfile.Session
}

// Open checks that identity can unwrap the file's data key and that the MAC
// holds. It does not decrypt values.
func Open(file []byte, identity age.Identity) (*Vault, error) {
	s, err := encfile.OpenIdentity(file, identity)
	if err != nil {
		return nil, err
	}
	return &Vault{session: s}, nil
}

// Names are the secret names, sorted.
func (v *Vault) Names() []string {
	if v == nil || v.session == nil {
		return nil
	}
	return v.session.Names()
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
}

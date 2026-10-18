package encfile

import (
	"filippo.io/age"
	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/crypto"
	"github.com/stefanpenner/shh/internal/envutil"
)

// Party is one public recipient on a vault. Key is an age recipient, not a secret.
type Party struct {
	Name string
	Key  string
}

// Session is one opened vault. Open checks the MAC and does not decrypt values.
type Session struct {
	file    *EncryptedFile
	dataKey []byte
}

// Open loads a vault file and checks that identity can read it.
func Open(file []byte, identity string) (*Session, error) {
	if len(file) == 0 {
		return nil, errors.New("vault file is empty")
	}
	if identity == "" {
		return nil, errors.New("identity is empty")
	}
	ef, err := LoadFromBytes(file)
	if err != nil {
		return nil, err
	}
	dataKey, err := resolveDataKey(ef, identity)
	if err != nil {
		return nil, err
	}
	if err := verifyMAC(ef, dataKey); err != nil {
		clearBytes(dataKey)
		return nil, err
	}
	return &Session{file: ef, dataKey: dataKey}, nil
}

// OpenIdentity is Open for a caller that holds an age.Identity in process, such
// as a TPM key loaded with age-plugin-tpm's library. The recipient can't be
// derived from such an identity, so each wrapped key is tried in name order.
// The MAC is checked before the session is returned. v1 files are refused:
// they predate per-recipient wrapping.
func OpenIdentity(file []byte, identity age.Identity) (*Session, error) {
	if len(file) == 0 {
		return nil, errors.New("vault file is empty")
	}
	if identity == nil {
		return nil, errors.New("identity is nil")
	}
	ef, err := LoadFromBytes(file)
	if err != nil {
		return nil, err
	}
	if ef.Version == 1 {
		return nil, errors.New("vault is format v1; run any shh write to upgrade it")
	}
	var dataKey []byte
	for _, name := range envutil.SortedKeys(ef.WrappedKeys) {
		if k, err := crypto.UnwrapDataKeyWith(ef.WrappedKeys[name], identity); err == nil {
			dataKey = k
			break
		}
	}
	if dataKey == nil {
		return nil, errors.New("this identity is not in the recipients list (no wrapped key could be unwrapped)")
	}
	if err := verifyMAC(ef, dataKey); err != nil {
		clearBytes(dataKey)
		return nil, err
	}
	return &Session{file: ef, dataKey: dataKey}, nil
}

// Recipients are the public recipients in name order. A closed session returns nil.
func (s *Session) Recipients() []Party {
	if s == nil || s.file == nil {
		return nil
	}
	names := envutil.SortedKeys(s.file.Recipients)
	out := make([]Party, 0, len(names))
	for _, name := range names {
		out = append(out, Party{Name: name, Key: s.file.Recipients[name]})
	}
	return out
}

// Names are the secret names in sorted order. The values stay encrypted.
func (s *Session) Names() []string {
	if s == nil || s.file == nil || s.dataKey == nil {
		return nil
	}
	return envutil.SortedKeys(s.file.Secrets)
}

// Secret decrypts one value. The name must be one of Names.
func (s *Session) Secret(name string) (string, error) {
	if s == nil || s.dataKey == nil || s.file == nil {
		return "", errors.New("vault is closed")
	}
	enc, ok := s.file.Secrets[name]
	if !ok {
		return "", errors.New("no such secret")
	}
	return crypto.DecryptValue(s.dataKey, name, enc)
}

// Close wipes the data key. Later Secret calls fail.
func (s *Session) Close() {
	if s == nil {
		return
	}
	clearBytes(s.dataKey)
	s.dataKey = nil
	s.file = nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

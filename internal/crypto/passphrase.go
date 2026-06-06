package crypto

import (
	"strings"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/argon2"
)

// Fixed, PUBLIC parameters for passphrase-derived ("brain") keys. These are a
// permanent contract: changing ANY of them changes the derived key, so an
// existing brain key would stop decrypting. NEVER change them — add a "-v2"
// label alongside if a future migration is needed.
//
// The salt is a constant label (not random): a brain key is a single-user
// failsafe, so identical passphrases intentionally yield identical keys, and
// recovery needs only the passphrase — nothing stored. argon2id makes each
// offline guess expensive; .env.enc is committed, so security rests entirely on
// passphrase entropy × this cost. Use a generated high-entropy passphrase.
const (
	passphraseSaltLabel = "shh-brainkey-v1"
	argonTime           = 3
	argonMemoryKiB      = 256 * 1024 // 256 MiB
	argonThreads        = 4
)

// IdentityFromPassphrase deterministically derives an age X25519 identity from a
// passphrase via argon2id. The result is an ordinary age key: its recipient is a
// normal age1… string and its identity is AGE-SECRET-KEY-1…, so the rest of shh
// (recipients map, wrapping, decryption) treats it like any other key.
func IdentityFromPassphrase(passphrase string) (*age.X25519Identity, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, errors.New("empty passphrase")
	}
	// The salt is the fixed public label itself (argon2 only needs >= 8 bytes).
	// Only the passphrase feeds the KDF; nothing sensitive is hashed elsewhere.
	salt := []byte(passphraseSaltLabel)
	seed := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemoryKiB, argonThreads, 32)

	s, err := bech32Encode("age-secret-key-", seed)
	if err != nil {
		return nil, errors.Wrap(err, "encode derived identity")
	}
	id, err := age.ParseX25519Identity(strings.ToUpper(s))
	if err != nil {
		return nil, errors.Wrap(err, "parse derived identity")
	}
	return id, nil
}

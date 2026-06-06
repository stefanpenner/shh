package cli

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/crypto"
)

func TestPassphraseRecipientDerives(t *testing.T) {
	const phrase = "correct-horse-battery-staple-anchor-violet-ledger-koala"
	orig := readSecret
	defer func() { readSecret = orig }()
	readSecret = func(string) (string, error) { return phrase, nil }

	rec, err := passphraseRecipient()
	require.NoError(t, err)

	id, err := crypto.IdentityFromPassphrase(phrase)
	require.NoError(t, err)
	require.Equal(t, id.Recipient().String(), rec, "CLI must derive the same recipient as the crypto layer")
}

func TestReadNewPassphraseRejectsMismatch(t *testing.T) {
	orig := readSecret
	defer func() { readSecret = orig }()
	calls := 0
	readSecret = func(string) (string, error) {
		calls++
		if calls == 1 {
			return "first", nil
		}
		return "second", nil
	}
	_, err := readNewPassphrase()
	require.Error(t, err, "mismatched confirmation must fail")
}

func TestReadNewPassphraseRejectsEmpty(t *testing.T) {
	orig := readSecret
	defer func() { readSecret = orig }()
	readSecret = func(string) (string, error) { return "   ", nil }
	_, err := readNewPassphrase()
	require.Error(t, err)
}

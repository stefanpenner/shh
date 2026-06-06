package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/crypto"
)

const testPhrase = "correct-horse-battery-staple-anchor-violet-ledger-koala"

func TestIdentityFromPassphraseIsDeterministic(t *testing.T) {
	a, err := crypto.IdentityFromPassphrase(testPhrase)
	require.NoError(t, err)
	b, err := crypto.IdentityFromPassphrase(testPhrase)
	require.NoError(t, err)
	require.Equal(t, a.String(), b.String(), "same passphrase → same identity")
	require.Equal(t, a.Recipient().String(), b.Recipient().String())
}

func TestIdentityFromPassphraseDiffers(t *testing.T) {
	a, err := crypto.IdentityFromPassphrase(testPhrase)
	require.NoError(t, err)
	b, err := crypto.IdentityFromPassphrase(testPhrase + "x")
	require.NoError(t, err)
	require.NotEqual(t, a.String(), b.String(), "different passphrase → different identity")
}

func TestIdentityFromPassphraseRejectsEmpty(t *testing.T) {
	_, err := crypto.IdentityFromPassphrase("")
	require.Error(t, err)
	_, err = crypto.IdentityFromPassphrase("   ")
	require.Error(t, err)
}

// The derived key must work through shh's real wrap/unwrap path.
func TestPassphraseKeyRoundTrips(t *testing.T) {
	id, err := crypto.IdentityFromPassphrase(testPhrase)
	require.NoError(t, err)

	dataKey, err := crypto.GenerateDataKey()
	require.NoError(t, err)
	wrapped, err := crypto.WrapDataKeyForRecipient(dataKey, id.Recipient().String())
	require.NoError(t, err)
	got, err := crypto.UnwrapDataKey(wrapped, id.String())
	require.NoError(t, err)
	require.Equal(t, dataKey, got)
}

// A passphrase key is an ordinary X25519 key, so it reports as extractable.
func TestPassphraseKeyIsExtractable(t *testing.T) {
	id, err := crypto.IdentityFromPassphrase(testPhrase)
	require.NoError(t, err)
	kind, extractable := crypto.RecipientKind(id.Recipient().String())
	require.Equal(t, "x25519", kind)
	require.True(t, extractable)
}

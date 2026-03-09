package crypto

import (
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptValue(t *testing.T) {
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello"},
		{"empty", ""},
		{"special chars", "p@ss w0rd!#$%^&*()"},
		{"unicode", "こんにちは世界"},
		{"url", "https://example.com?foo=bar&baz=1"},
		{"long value", strings.Repeat("a", 10000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := EncryptValue(dataKey, "TEST_KEY", tt.plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, tt.plaintext, enc, "encrypted should differ from plaintext")

			dec, err := DecryptValue(dataKey, "TEST_KEY", enc)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, dec)
		})
	}
}

func TestEncryptValue_UniqueNonces(t *testing.T) {
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	enc1, err := EncryptValue(dataKey, "KEY", "same")
	require.NoError(t, err)
	enc2, err := EncryptValue(dataKey, "KEY", "same")
	require.NoError(t, err)

	assert.NotEqual(t, enc1, enc2, "two encryptions of same plaintext should differ (unique nonces)")
}

func TestDecryptValue_InvalidBase64(t *testing.T) {
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	_, err = DecryptValue(dataKey, "KEY", "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecryptValue_TamperedCiphertext(t *testing.T) {
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	enc, err := EncryptValue(dataKey, "KEY", "secret")
	require.NoError(t, err)

	tampered := enc[:len(enc)-2] + "XX"
	_, err = DecryptValue(dataKey, "KEY", tampered)
	assert.Error(t, err)
}

func TestDecryptValue_WrongKey(t *testing.T) {
	key1, err := GenerateDataKey()
	require.NoError(t, err)
	key2, err := GenerateDataKey()
	require.NoError(t, err)

	enc, err := EncryptValue(key1, "KEY", "secret")
	require.NoError(t, err)

	_, err = DecryptValue(key2, "KEY", enc)
	assert.Error(t, err)
}

func TestAAD_PreventsValueSwapping(t *testing.T) {
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	enc, err := EncryptValue(dataKey, "KEY_A", "secret_a")
	require.NoError(t, err)

	_, err = DecryptValue(dataKey, "KEY_B", enc)
	assert.Error(t, err, "decrypting with wrong key name AAD should fail")

	dec, err := DecryptValue(dataKey, "KEY_A", enc)
	require.NoError(t, err)
	assert.Equal(t, "secret_a", dec)
}

func TestPublicKeyFrom(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	pub, err := PublicKeyFrom(identity.String())
	require.NoError(t, err)
	assert.Equal(t, identity.Recipient().String(), pub)
}

func TestWrapUnwrapDataKey(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	priv := identity.String()
	pub := identity.Recipient().String()

	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	wrapped, err := WrapDataKeyForRecipient(dataKey, pub)
	require.NoError(t, err)

	unwrapped, err := UnwrapDataKey(wrapped, priv)
	require.NoError(t, err)

	assert.Equal(t, dataKey, unwrapped)
}

func TestWrapDataKey_PerRecipient(t *testing.T) {
	id1, _ := age.GenerateX25519Identity()
	id2, _ := age.GenerateX25519Identity()
	priv1, pub1 := id1.String(), id1.Recipient().String()
	priv2, pub2 := id2.String(), id2.Recipient().String()
	dataKey, err := GenerateDataKey()
	require.NoError(t, err)

	recipients := map[string]string{"alice": pub1, "bob": pub2}
	wrappedKeys, err := WrapDataKeyPerRecipient(dataKey, recipients)
	require.NoError(t, err)

	unwrapped1, err := UnwrapDataKey(wrappedKeys["alice"], priv1)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped1)

	unwrapped2, err := UnwrapDataKey(wrappedKeys["bob"], priv2)
	require.NoError(t, err)
	assert.Equal(t, dataKey, unwrapped2)

	// Cross-decryption should fail
	_, err = UnwrapDataKey(wrappedKeys["alice"], priv2)
	assert.Error(t, err)
}

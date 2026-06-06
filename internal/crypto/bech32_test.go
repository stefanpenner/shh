package crypto

import (
	"crypto/rand"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

// TestBech32MatchesAge cross-validates our Bech32 encoder against age's own
// decoder: age must accept every "age-secret-key-…" string we produce and
// round-trip it to the byte-identical canonical form. This pins our encoder to
// the real consumer without relying on a separately-implemented decoder.
func TestBech32MatchesAge(t *testing.T) {
	for i := 0; i < 256; i++ {
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		require.NoError(t, err)

		s, err := bech32Encode("age-secret-key-", seed)
		require.NoError(t, err)

		upper := strings.ToUpper(s)
		id, err := age.ParseX25519Identity(upper)
		require.NoError(t, err, "age must parse our bech32 output")
		require.Equal(t, upper, id.String(), "encoding must be canonical")
	}
}

// Known-answer: the empty-data checksum for hrp "a" is the BIP-173 vector
// "a12uel5l" — anchors the polymod/checksum independently of age.
func TestBech32KnownAnswer(t *testing.T) {
	s, err := bech32Encode("a", []byte{})
	require.NoError(t, err)
	require.Equal(t, "a12uel5l", s)
}

func TestConvertBitsRoundTripShape(t *testing.T) {
	// 32 bytes (256 bits) → 52 five-bit groups (256/5 = 51.2, padded up).
	out, err := convertBits(make([]byte, 32), 8, 5, true)
	require.NoError(t, err)
	require.Len(t, out, 52)
}

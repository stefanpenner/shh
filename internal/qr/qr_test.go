package qr

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizePayload_TrimsAndStripsPrefix(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	secret := id.String()

	cases := []struct {
		in   string
		want string
	}{
		{secret, secret},
		{"  " + secret + "\n", secret},
		{"SHH_AGE_KEY=" + secret, secret},
		{"# comment\n" + secret + "\n", secret},
		{"export SHH_AGE_KEY=" + secret, secret},
	}
	for _, tc := range cases {
		got := NormalizePayload(tc.in)
		assert.Equal(t, tc.want, got, "in=%q", tc.in)
	}
}

func TestNormalizePayload_Empty(t *testing.T) {
	assert.Equal(t, "", NormalizePayload(""))
	assert.Equal(t, "", NormalizePayload("   \n# only comment\n"))
}

func TestEncodeDecodePNG_RoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	secret := id.String()

	var buf bytes.Buffer
	require.NoError(t, EncodePNG(secret, &buf))
	assert.Greater(t, buf.Len(), 100, "PNG should be non-trivial")

	got, err := DecodePNG(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, secret, got, "QR round-trip must preserve AGE-SECRET-KEY exactly")
}

func TestEncodeDecodeFile_RoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	secret := id.String()

	path := filepath.Join(t.TempDir(), "recovery.png")
	require.NoError(t, EncodeFile(secret, path))

	// File must exist and be a PNG
	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Greater(t, st.Size(), int64(100))

	got, err := DecodeFile(path)
	require.NoError(t, err)
	assert.Equal(t, secret, NormalizePayload(got))
	assert.Equal(t, secret, got)
}

func TestDecodeFile_RejectsNonQR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-qr.png")
	// minimal invalid file
	require.NoError(t, os.WriteFile(path, []byte("not a png"), 0o600))
	_, err := DecodeFile(path)
	require.Error(t, err)
}

func TestEncodePNG_RejectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := EncodePNG("", &buf)
	require.Error(t, err)
}

func TestIsAgeIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	assert.True(t, IsAgeIdentity(id.String()))
	assert.False(t, IsAgeIdentity("not-a-key"))
	assert.False(t, IsAgeIdentity("correct horse battery staple phrase here"))
	assert.True(t, IsAgeIdentity("  "+id.String()+"\n"))
}

func TestChecksumHint(t *testing.T) {
	s := "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	h := ChecksumHint(s)
	assert.Equal(t, "ABCD…WXYZ", h)
	assert.True(t, len(h) < 40)
	assert.NotContains(t, h, "AGE-")
}

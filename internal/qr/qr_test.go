package qr

import (
	"bytes"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	goqrcode "github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustSecret(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id.String()
}

func TestNormalizePayload_TrimsAndStripsPrefix(t *testing.T) {
	secret := mustSecret(t)
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
		assert.Equal(t, tc.want, NormalizePayload(tc.in), "in=%q", tc.in)
	}
}

func TestNormalizePayload_EmptyAndEvil(t *testing.T) {
	assert.Equal(t, "", NormalizePayload(""))
	assert.Equal(t, "", NormalizePayload("   \n# only comment\n"))
	assert.Equal(t, "", NormalizePayload("a\x00b"))
}

func TestEncodeDecodePNG_RoundTrip(t *testing.T) {
	secret := mustSecret(t)
	var buf bytes.Buffer
	require.NoError(t, EncodePNG(secret, &buf))
	assert.Greater(t, buf.Len(), 100)

	got, err := DecodePNG(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestEncodeDecodeFile_RoundTrip(t *testing.T) {
	secret := mustSecret(t)
	path := filepath.Join(t.TempDir(), "recovery.png")
	require.NoError(t, EncodeFile(secret, path))

	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	got, err := DecodeFile(path)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestEncodePNG_RejectsEmptyAndURLs(t *testing.T) {
	var buf bytes.Buffer
	require.Error(t, EncodePNG("", &buf))
	require.Error(t, EncodePNG("https://evil.example/phish", &buf))
	require.Error(t, EncodePNG("http://evil.example/", &buf))
	require.Error(t, EncodePNG("javascript:alert(1)", &buf))
	require.Error(t, EncodePNG("not-a-key", &buf))
	require.Error(t, EncodePNG("AGE-SECRET-KEY-1SHORT", &buf))
}

func TestDecode_RejectsURLQR(t *testing.T) {
	// Craft QR containing a phishing URL — decode must refuse.
	code, err := goqrcode.New("https://evil.example/steal", goqrcode.Medium)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, code.Write(256, &buf))
	_, err = DecodePNG(buf.Bytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

func TestDecode_RejectsNonQRAndHuge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-qr.png")
	require.NoError(t, os.WriteFile(path, []byte("not a png"), 0o600))
	_, err := DecodeFile(path)
	require.Error(t, err)

	big := filepath.Join(t.TempDir(), "big.bin")
	require.NoError(t, os.WriteFile(big, make([]byte, MaxImageBytes+10), 0o600))
	_, err = DecodeFile(big)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestDecodeImage_RejectsHugeDimensions(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, MaxImageDim+1, 10))
	for y := 0; y < 10; y++ {
		for x := 0; x < MaxImageDim+1; x++ {
			img.SetGray(x, y, color.Gray{Y: 255})
		}
	}
	_, err := DecodeImage(img)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimensions")
}

func TestParseExtractableSecret(t *testing.T) {
	secret := mustSecret(t)
	got, err := ParseExtractableSecret("SHH_AGE_KEY=" + secret)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	_, err = ParseExtractableSecret("https://phish")
	require.Error(t, err)
}

func TestIsExtractableAgeSecret(t *testing.T) {
	secret := mustSecret(t)
	assert.True(t, IsExtractableAgeSecret(secret))
	assert.False(t, IsExtractableAgeSecret("https://x"))
	assert.False(t, IsExtractableAgeSecret("AGE-PLUGIN-something"))
}

func TestChecksumHint(t *testing.T) {
	s := "AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	h := ChecksumHint(s)
	assert.True(t, strings.Contains(h, "…"))
	assert.NotContains(t, h, "AGE-")
	assert.True(t, len(h) < 40)
}

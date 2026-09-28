package qr

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	goqrcode "github.com/skip2/go-qrcode"
	"github.com/stretchr/testify/require"
)

func TestVaultQR_RoundTrip(t *testing.T) {
	vault := make([]byte, rawChunk+80)
	_, err := rand.Read(vault)
	require.NoError(t, err)
	dir := t.TempDir()
	n, err := WriteVaultQRs(vault, dir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 2)

	got, err := ReadVaultQRs(dir)
	require.NoError(t, err)
	require.Equal(t, vault, got)

	one := filepath.Join(dir, "01.png")
	if runtime.GOOS != "windows" {
		st, err := os.Stat(one)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	_, err = ReadVaultQRs(one)
	require.Error(t, err, "one code of a multi-code sheet must fail")
}

func TestVaultQR_OrderDoesNotMatter(t *testing.T) {
	vault := []byte("version = 2\nmac = \"abc\"\n")
	pngs, err := EncodeVaultPNGs(vault)
	require.NoError(t, err)
	require.NotEmpty(t, pngs)

	// Decode each PNG to a frame, then assemble in reverse.
	var frames []Frame
	for i := len(pngs) - 1; i >= 0; i-- {
		text := decodePNGText(t, pngs[i])
		f, err := ParseFrame(text)
		require.NoError(t, err)
		frames = append(frames, f)
	}
	packed, err := Assemble(frames)
	require.NoError(t, err)
	got, err := gunzipVault(packed)
	require.NoError(t, err)
	require.Equal(t, vault, got)
}

func TestVaultQR_RejectsHostileFrames(t *testing.T) {
	good, err := SplitVault([]byte("vault-bytes"))
	require.NoError(t, err)
	text, err := FormatFrame(good[0])
	require.NoError(t, err)

	cases := []string{
		"",
		"https://evil.example/steal",
		"javascript:alert(1)",
		"SHHENV1 0 1 AAAAAAAA AAAA",
		"SHHENV1 99 1 AAAAAAAA AAAA",
		"SHHENV1 1 0 AAAAAAAA AAAA",
		"SHHENV1 1 2 AAAAAAAA AAAA",
		"SHHENV1 1 1 ZZZZZZZZ AAAA",
		text + " extra",
	}
	for _, c := range cases {
		_, err := ParseFrame(c)
		require.Error(t, err)
	}

	f := good[0]
	f.Data = append([]byte(nil), f.Data...)
	f.Data[0] ^= 0xff
	_, err = Assemble([]Frame{f})
	require.Error(t, err, "sum must fail after a changed byte")

	_, err = SplitVault(nil)
	require.Error(t, err)
	_, err = SplitVault(bytesRepeat(t, 1, MaxParts*rawChunk+1))
	require.Error(t, err)
}

func TestVaultQR_GzipFitsOneMaxCode(t *testing.T) {
	vault := bytesRepeat(t, 0x11, 7000)
	pngs, err := EncodeVaultPNGs(vault)
	require.NoError(t, err)
	require.Len(t, pngs, 1)
	got := decodePNGText(t, pngs[0])
	require.LessOrEqual(t, len(got), maxFrameChars)
}

func TestVaultQR_URLImageIsNotAVault(t *testing.T) {
	code, err := goqrcode.New("https://evil.example/phish", goqrcode.Medium)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "url.png")
	require.NoError(t, code.WriteFile(256, path))
	_, err = ReadVaultQRs(path)
	require.Error(t, err)
}

func decodePNGText(t *testing.T, png []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "one.png")
	require.NoError(t, os.WriteFile(path, png, 0o600))
	text, err := decodeFileText(path)
	require.NoError(t, err)
	return text
}

func bytesRepeat(t *testing.T, b byte, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

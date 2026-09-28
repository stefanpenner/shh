package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stefanpenner/shh/internal/encfile"
)

func TestPaperEncodeDecode(t *testing.T) {
	dir := useTempDir(t)
	_, pub := generateTestKey(t)
	ef, err := encfile.EncryptSecrets(
		map[string]string{"API": "real-value"},
		map[string]string{"alice": pub},
	)
	require.NoError(t, err)
	src := filepath.Join(dir, ".env.enc")
	require.NoError(t, encfile.Save(src, ef))
	raw, err := os.ReadFile(src)
	require.NoError(t, err)

	sheet := filepath.Join(dir, "sheet")
	require.NoError(t, cmdPaperEncode(src, sheet))
	restored := filepath.Join(dir, "restored.env.enc")
	require.NoError(t, cmdPaperDecode(sheet, restored))
	got, err := os.ReadFile(restored)
	require.NoError(t, err)
	require.Equal(t, raw, got)
	if runtime.GOOS != "windows" {
		st, err := os.Stat(restored)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	}

	err = cmdPaperDecode(sheet, restored)
	require.Error(t, err, "decode must not replace an existing file")

	plain := filepath.Join(dir, "plain.env")
	require.NoError(t, os.WriteFile(plain, []byte("API=nope\n"), 0o600))
	err = cmdPaperEncode(plain, filepath.Join(dir, "nope"))
	require.Error(t, err)
}

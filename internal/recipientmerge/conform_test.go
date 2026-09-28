package recipientmerge

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecide_Conform(t *testing.T) {
	_, tr, err := Decide(true)
	require.NoError(t, err)
	conformTrace(t, tr)

	_, tr, err = Decide(false)
	require.ErrorIs(t, err, ErrSetsDiffer)
	require.Empty(t, tr)
}

func TestConform_RejectsMergeWhenSetsDiffer(t *testing.T) {
	s := Init()
	bad := TraceEntry{Action: "Merge", Pre: s, Post: s.Merge()}
	if conformFile(t, []TraceEntry{bad}) == 0 {
		t.Fatal("conform accepted a merge from an unequal set")
	}
}

func TestGeneratedMatchesSpec(t *testing.T) {
	bin, err := exec.LookPath("specgen")
	if err != nil {
		t.Skip("specgen is not on PATH")
	}
	dir := t.TempDir()
	root := moduleRoot(t)
	cmd := exec.Command(bin, "-o", dir, "-p", "recipientmerge", filepath.Join("specs", "RecipientMerge.tla"))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	got, err := os.ReadFile(filepath.Join(dir, "spec.go"))
	require.NoError(t, err)
	want, err := os.ReadFile("spec.go")
	require.NoError(t, err)
	require.Equal(t, specBody(want), specBody(got))
}

func conformTrace(t *testing.T, tr []TraceEntry) {
	t.Helper()
	if conformFile(t, tr) != 0 {
		t.Fatal("conform rejected a legal trace")
	}
}

func conformFile(t *testing.T, tr []TraceEntry) int {
	t.Helper()
	bin, err := exec.LookPath("conform")
	if err != nil {
		t.Skip("conform is not on PATH")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range tr {
		require.NoError(t, enc.Encode(e))
	}
	path := filepath.Join(t.TempDir(), "trace.ndjson")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	cmd := exec.Command(bin, "-spec", filepath.Join(moduleRoot(t), "specs", "RecipientMerge.tla"), path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("conform: %v\n%s", err, out)
	}
	t.Logf("conform: %s", out)
	return ee.ExitCode()
}

func specBody(b []byte) string {
	s := string(b)
	i := strings.Index(s, "package ")
	if i < 0 {
		return s
	}
	return s[i:]
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

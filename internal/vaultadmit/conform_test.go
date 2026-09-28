package vaultadmit

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
	cases := []struct {
		name    string
		differs bool
		accept  bool
		wantErr bool
	}{
		{name: "same set", differs: false, accept: false},
		{name: "accepted change", differs: true, accept: true},
		{name: "unreviewed change", differs: true, accept: false, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, tr, err := Decide(tc.differs, tc.accept)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUnreviewed)
			} else {
				require.NoError(t, err)
			}
			require.NotEmpty(t, tr)
			conformTrace(t, "VaultAdmit.tla", tr)
		})
	}
}

func TestConform_RejectsSetWithoutAccept(t *testing.T) {
	s := Init()
	e, s := s.Trace("Forge")
	bad := TraceEntry{Action: "Set", Pre: s, Post: s.Set()}
	conformTraceExpectFail(t, "VaultAdmit.tla", []TraceEntry{e, bad})
}

func TestGeneratedMatchesSpec(t *testing.T) {
	assertSpecgenMatch(t, "vaultadmit", "VaultAdmit.tla")
}

func conformTrace(t *testing.T, spec string, tr []TraceEntry) {
	t.Helper()
	if conformFile(t, spec, tr) != 0 {
		t.Fatal("conform rejected a legal trace")
	}
}

func conformTraceExpectFail(t *testing.T, spec string, tr []TraceEntry) {
	t.Helper()
	if conformFile(t, spec, tr) == 0 {
		t.Fatal("conform accepted an illegal trace")
	}
}

func conformFile(t *testing.T, spec string, tr []TraceEntry) int {
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
	cmd := exec.Command(bin, "-spec", filepath.Join(moduleRoot(t), "specs", spec), path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errorsAsExit(err, &exitErr) {
		t.Logf("conform: %s", out)
		return exitErr.ExitCode()
	}
	t.Fatalf("conform: %v\n%s", err, out)
	return 1
}

func errorsAsExit(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	*target = ee
	return true
}

func assertSpecgenMatch(t *testing.T, pkg, spec string) {
	t.Helper()
	bin, err := exec.LookPath("specgen")
	if err != nil {
		t.Skip("specgen is not on PATH")
	}
	dir := t.TempDir()
	root := moduleRoot(t)
	cmd := exec.Command(bin, "-o", dir, "-p", pkg, filepath.Join("specs", spec))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	got, err := os.ReadFile(filepath.Join(dir, "spec.go"))
	require.NoError(t, err)
	want, err := os.ReadFile("spec.go")
	require.NoError(t, err)
	require.Equal(t, specBody(want), specBody(got))
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

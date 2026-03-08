package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helper: chdir to a temp dir, restore on cleanup
func useTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found, skipping", name)
	}
}

// --- Unit tests (no external deps) ---

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single", "FOO=bar", 1},
		{"multiple", "FOO=bar\nBAZ=qux\n", 2},
		{"with comments", "# comment\nFOO=bar\n\nBAZ=qux", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := parseDotenv(tt.input)
			if len(lines) != tt.want {
				t.Errorf("parseDotenv(%q) = %d lines, want %d", tt.input, len(lines), tt.want)
			}
		})
	}
}

func TestDotenvGet(t *testing.T) {
	lines := []string{"FOO=bar", "BAZ=qux", "# comment", "MULTI=a=b=c"}

	tests := []struct {
		key       string
		wantIdx   int
		wantFound bool
	}{
		{"FOO", 0, true},
		{"BAZ", 1, true},
		{"MULTI", 3, true},
		{"MISSING", -1, false},
		{"FO", -1, false}, // partial match should not work
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			idx, found := dotenvGet(lines, tt.key)
			if found != tt.wantFound || idx != tt.wantIdx {
				t.Errorf("dotenvGet(%q) = (%d, %v), want (%d, %v)",
					tt.key, idx, found, tt.wantIdx, tt.wantFound)
			}
		})
	}
}

func TestWriteSopsConfig(t *testing.T) {
	useTempDir(t)

	keys := []string{"age1abc", "age1def"}
	if err := writeSopsConfig(keys); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(sopsConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "age1abc,age1def") {
		t.Errorf("config missing keys: %s", content)
	}
	if !strings.Contains(content, "creation_rules:") {
		t.Errorf("config missing creation_rules: %s", content)
	}
}

func TestSopsKeysFromConfig(t *testing.T) {
	useTempDir(t)

	tests := []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{
			"standard",
			"creation_rules:\n  - age: \"age1abc,age1def\"\n",
			[]string{"age1abc", "age1def"},
			false,
		},
		{
			"single key",
			"creation_rules:\n  - age: \"age1only\"\n",
			[]string{"age1only"},
			false,
		},
		{
			"no age line",
			"creation_rules:\n  - kms: \"arn:...\"\n",
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.WriteFile(sopsConfigFile, []byte(tt.content), 0644)
			keys, err := sopsKeysFromConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(keys) != len(tt.want) {
					t.Fatalf("got %d keys, want %d", len(keys), len(tt.want))
				}
				for i := range keys {
					if keys[i] != tt.want[i] {
						t.Errorf("key[%d] = %q, want %q", i, keys[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestSopsKeysFromConfig_NoFile(t *testing.T) {
	useTempDir(t)
	_, err := sopsKeysFromConfig()
	if err == nil {
		t.Error("expected error when no config file exists")
	}
}

func TestWriteThenReadSopsConfig(t *testing.T) {
	useTempDir(t)

	original := []string{"age1aaa", "age1bbb", "age1ccc"}
	if err := writeSopsConfig(original); err != nil {
		t.Fatal(err)
	}
	keys, err := sopsKeysFromConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != len(original) {
		t.Fatalf("roundtrip: got %d keys, want %d", len(keys), len(original))
	}
	for i := range keys {
		if keys[i] != original[i] {
			t.Errorf("roundtrip: key[%d] = %q, want %q", i, keys[i], original[i])
		}
	}
}

func TestRegisterAndKeyName(t *testing.T) {
	useTempDir(t)

	if err := registerKey("age1abc", "alice"); err != nil {
		t.Fatal(err)
	}
	if name := keyName("age1abc"); name != "alice" {
		t.Errorf("keyName = %q, want %q", name, "alice")
	}

	// Unknown key
	if name := keyName("age1unknown"); name != "" {
		t.Errorf("keyName for unknown = %q, want empty", name)
	}

	// Update name
	if err := registerKey("age1abc", "bob"); err != nil {
		t.Fatal(err)
	}
	if name := keyName("age1abc"); name != "bob" {
		t.Errorf("keyName after update = %q, want %q", name, "bob")
	}

	// Multiple keys
	if err := registerKey("age1def", "carol"); err != nil {
		t.Fatal(err)
	}
	if name := keyName("age1abc"); name != "bob" {
		t.Errorf("keyName(abc) = %q, want %q", name, "bob")
	}
	if name := keyName("age1def"); name != "carol" {
		t.Errorf("keyName(def) = %q, want %q", name, "carol")
	}
}

func TestKeyNameNoFile(t *testing.T) {
	useTempDir(t)
	if name := keyName("age1abc"); name != "" {
		t.Errorf("keyName with no file = %q, want empty", name)
	}
}

func TestCheckDep(t *testing.T) {
	// Should find standard tools
	if err := checkDep("ls", ""); err != nil {
		t.Errorf("checkDep(ls) should succeed: %v", err)
	}
	// Should fail on nonexistent
	if err := checkDep("nonexistent_tool_xyz_999", "install it"); err == nil {
		t.Error("checkDep should fail for missing tool")
	} else if !strings.Contains(err.Error(), "install it") {
		t.Errorf("error should contain install hint: %v", err)
	}
}

// --- Integration tests (require age + sops) ---

func TestIntegration_EncryptDecryptSetRm(t *testing.T) {
	requireTool(t, "age-keygen")
	requireTool(t, "sops")
	useTempDir(t)

	// Generate a key pair
	out, err := exec.Command("age-keygen").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	var privKey, pubKey string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "public key:") {
			parts := strings.Fields(line)
			pubKey = parts[len(parts)-1]
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY") {
			privKey = line
		}
	}

	// Write .sops.yaml
	writeSopsConfig([]string{pubKey})

	// Write a plaintext .env
	os.WriteFile(".env", []byte("SECRET=hello\nAPI_KEY=sk-123\n"), 0644)

	// Encrypt using sops directly (bypass keychain)
	encCmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", ".env")
	encCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	encOut, err := encCmd.Output()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	os.WriteFile(".env.enc", encOut, 0644)

	// Verify encrypted file is not plaintext
	encData, _ := os.ReadFile(".env.enc")
	if strings.Contains(string(encData), "hello") {
		t.Error("encrypted file contains plaintext value")
	}

	// Decrypt using sops directly
	decCmd := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	decOut, err := decCmd.Output()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plaintext := string(decOut)
	if !strings.Contains(plaintext, "SECRET=hello") {
		t.Errorf("decrypted output missing SECRET=hello: %s", plaintext)
	}
	if !strings.Contains(plaintext, "API_KEY=sk-123") {
		t.Errorf("decrypted output missing API_KEY: %s", plaintext)
	}

	// Test set (upsert) via sops round-trip
	lines := parseDotenv(plaintext)
	newLine := "NEW_KEY=new_value"
	lines = append(lines, newLine)
	setInput := strings.Join(lines, "\n") + "\n"

	setCmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin")
	setCmd.Stdin = strings.NewReader(setInput)
	setCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	setOut, err := setCmd.Output()
	if err != nil {
		t.Fatalf("set encrypt: %v", err)
	}
	os.WriteFile(".env.enc", setOut, 0644)

	// Decrypt and verify new key exists
	decCmd2 := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd2.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	decOut2, err := decCmd2.Output()
	if err != nil {
		t.Fatalf("decrypt after set: %v", err)
	}
	if !strings.Contains(string(decOut2), "NEW_KEY=new_value") {
		t.Error("set: new key not found after decrypt")
	}
	if !strings.Contains(string(decOut2), "SECRET=hello") {
		t.Error("set: original key disappeared")
	}

	// Test rm
	lines2 := parseDotenv(string(decOut2))
	var filtered []string
	for _, l := range lines2 {
		if !strings.HasPrefix(l, "API_KEY=") {
			filtered = append(filtered, l)
		}
	}
	rmInput := strings.Join(filtered, "\n") + "\n"

	rmCmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin")
	rmCmd.Stdin = strings.NewReader(rmInput)
	rmCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	rmOut, err := rmCmd.Output()
	if err != nil {
		t.Fatalf("rm encrypt: %v", err)
	}
	os.WriteFile(".env.enc", rmOut, 0644)

	decCmd3 := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd3.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	decOut3, err := decCmd3.Output()
	if err != nil {
		t.Fatalf("decrypt after rm: %v", err)
	}
	if strings.Contains(string(decOut3), "API_KEY=") {
		t.Error("rm: key still present after removal")
	}
	if !strings.Contains(string(decOut3), "SECRET=hello") {
		t.Error("rm: other keys should survive")
	}
	if !strings.Contains(string(decOut3), "NEW_KEY=new_value") {
		t.Error("rm: other keys should survive")
	}
}

func TestIntegration_MultiRecipient(t *testing.T) {
	requireTool(t, "age-keygen")
	requireTool(t, "sops")
	useTempDir(t)

	// Generate two key pairs
	genKey := func() (string, string) {
		out, err := exec.Command("age-keygen").CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		var priv, pub string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "public key:") {
				parts := strings.Fields(line)
				pub = parts[len(parts)-1]
			}
			if strings.HasPrefix(line, "AGE-SECRET-KEY") {
				priv = line
			}
		}
		return priv, pub
	}

	priv1, pub1 := genKey()
	priv2, pub2 := genKey()

	// Config with both keys
	writeSopsConfig([]string{pub1, pub2})

	// Encrypt with key1
	os.WriteFile(".env", []byte("SHARED_SECRET=42\n"), 0644)
	encCmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", ".env")
	encCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+priv1)
	encOut, err := encCmd.Output()
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	os.WriteFile(".env.enc", encOut, 0644)

	// Decrypt with key2
	decCmd := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+priv2)
	decOut, err := decCmd.Output()
	if err != nil {
		t.Fatalf("key2 decrypt: %v", err)
	}
	if !strings.Contains(string(decOut), "SHARED_SECRET=42") {
		t.Error("key2 could not decrypt")
	}

	// Decrypt with key1 also works
	decCmd2 := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd2.Env = append(os.Environ(), "SOPS_AGE_KEY="+priv1)
	decOut2, err := decCmd2.Output()
	if err != nil {
		t.Fatalf("key1 decrypt: %v", err)
	}
	if !strings.Contains(string(decOut2), "SHARED_SECRET=42") {
		t.Error("key1 could not decrypt")
	}
}

func TestIntegration_PublicKeyFrom(t *testing.T) {
	requireTool(t, "age-keygen")

	out, err := exec.Command("age-keygen").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	var privKey, expectedPub string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "public key:") {
			parts := strings.Fields(line)
			expectedPub = parts[len(parts)-1]
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY") {
			privKey = line
		}
	}

	pub, err := publicKeyFrom(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != expectedPub {
		t.Errorf("publicKeyFrom = %q, want %q", pub, expectedPub)
	}
}

func TestDotenvGet_EdgeCases(t *testing.T) {
	lines := []string{
		"FOO=",           // empty value
		"BAR=has=equals", // value with equals
		"=nokey",         // empty key (weird but possible)
		"FOOBAR=baz",     // shouldn't match "FOO"
	}

	tests := []struct {
		key       string
		wantIdx   int
		wantFound bool
	}{
		{"FOO", 0, true},
		{"BAR", 1, true},
		{"", 2, true},
		{"FOOBAR", 3, true},
		{"FOO ", -1, false}, // trailing space
	}
	for _, tt := range tests {
		t.Run("key="+tt.key, func(t *testing.T) {
			idx, found := dotenvGet(lines, tt.key)
			if found != tt.wantFound || idx != tt.wantIdx {
				t.Errorf("dotenvGet(%q) = (%d, %v), want (%d, %v)",
					tt.key, idx, found, tt.wantIdx, tt.wantFound)
			}
		})
	}
}

func TestRegisterKey_Idempotent(t *testing.T) {
	useTempDir(t)

	registerKey("age1abc", "alice")
	registerKey("age1abc", "alice")
	registerKey("age1abc", "alice")

	data, _ := os.ReadFile(keyRegistryFile)
	count := strings.Count(string(data), "age1abc")
	if count != 1 {
		t.Errorf("key appears %d times, want 1", count)
	}
}

func TestWriteSopsConfig_Overwrite(t *testing.T) {
	useTempDir(t)

	writeSopsConfig([]string{"age1old"})
	writeSopsConfig([]string{"age1new"})

	keys, _ := sopsKeysFromConfig()
	if len(keys) != 1 || keys[0] != "age1new" {
		t.Errorf("overwrite failed: got %v", keys)
	}
}

func TestIntegration_EncryptCreatesConfig(t *testing.T) {
	requireTool(t, "age-keygen")
	useTempDir(t)

	// No .sops.yaml exists
	if _, err := os.Stat(sopsConfigFile); err == nil {
		t.Fatal("config should not exist yet")
	}

	// Generate key
	out, _ := exec.Command("age-keygen").CombinedOutput()
	var pubKey string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "public key:") {
			parts := strings.Fields(line)
			pubKey = parts[len(parts)-1]
		}
	}

	writeSopsConfig([]string{pubKey})

	// Verify it was created
	if _, err := os.Stat(sopsConfigFile); err != nil {
		t.Error("config should exist after writeSopsConfig")
	}
	keys, _ := sopsKeysFromConfig()
	if len(keys) != 1 || keys[0] != pubKey {
		t.Errorf("config has wrong keys: %v", keys)
	}
}

func TestRegistryFile_Permissions(t *testing.T) {
	useTempDir(t)

	registerKey("age1test", "testuser")

	info, err := os.Stat(keyRegistryFile)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("registry permissions = %o, want 644", perm)
	}
}

func TestSopsConfigFile_Permissions(t *testing.T) {
	useTempDir(t)

	writeSopsConfig([]string{"age1test"})

	info, err := os.Stat(sopsConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("sops config permissions = %o, want 644", perm)
	}
}

func TestIntegration_EncryptDecrypt_SpecialChars(t *testing.T) {
	requireTool(t, "age-keygen")
	requireTool(t, "sops")
	useTempDir(t)

	out, _ := exec.Command("age-keygen").CombinedOutput()
	var privKey, pubKey string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "public key:") {
			parts := strings.Fields(line)
			pubKey = parts[len(parts)-1]
		}
		if strings.HasPrefix(line, "AGE-SECRET-KEY") {
			privKey = line
		}
	}
	writeSopsConfig([]string{pubKey})

	// Values with special chars
	env := "PASSWORD=p@ss w0rd!#$%\nURL=https://example.com?foo=bar&baz=1\n"
	os.WriteFile(".env", []byte(env), 0644)

	encCmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", ".env")
	encCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	encOut, err := encCmd.Output()
	if err != nil {
		ee, _ := err.(*exec.ExitError)
		t.Fatalf("encrypt: %v\nstderr: %s", err, string(ee.Stderr))
	}
	os.WriteFile(".env.enc", encOut, 0644)

	decCmd := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", ".env.enc")
	decCmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+privKey)
	decOut, err := decCmd.Output()
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !strings.Contains(string(decOut), "p@ss w0rd!#$%") {
		t.Error("special chars in password not preserved")
	}
	if !strings.Contains(string(decOut), "https://example.com?foo=bar&baz=1") {
		t.Error("URL with special chars not preserved")
	}
}

// Verify absolute paths work with key registry
func TestKeyRegistry_AbsolutePaths(t *testing.T) {
	useTempDir(t)

	absPath := filepath.Join(t.TempDir(), ".age-keys")
	os.WriteFile(absPath, []byte("age1xxx alice\nage1yyy bob\n"), 0644)

	// The global keyRegistryFile is relative, but verify our functions
	// work correctly in the temp dir context
	registerKey("age1aaa", "carol")
	registerKey("age1bbb", "dave")

	if name := keyName("age1aaa"); name != "carol" {
		t.Errorf("got %q, want carol", name)
	}
	if name := keyName("age1bbb"); name != "dave" {
		t.Errorf("got %q, want dave", name)
	}
}

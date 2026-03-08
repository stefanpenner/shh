package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	keychainService = "shh-age-key"
	sopsConfigFile  = ".sops.yaml"
	keyRegistryFile = ".age-keys"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "encrypt":
		err = cmdEncrypt(os.Args[2:])
	case "decrypt":
		err = cmdDecrypt(os.Args[2:])
	case "edit":
		err = cmdEdit(os.Args[2:])
	case "set":
		err = cmdSet(os.Args[2:])
	case "rm":
		err = cmdRm(os.Args[2:])
	case "keys":
		err = cmdKeys(os.Args[2:])
	case "shell":
		err = cmdShell(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`Usage: shh <command>

Commands:
  init                      Generate age key and store in Keychain
  init --from-ssh [path]    Derive age key from SSH ed25519 key

  encrypt <file>            Encrypt a .env file → .env.enc
  decrypt <file>            Print decrypted contents
  edit <file>               Edit secrets in $EDITOR
  shell <file>              Start a subshell with secrets loaded

  set <file> <KEY> <VALUE>  Add or update a secret
  rm <file> <KEY>           Remove a secret

  keys list                 List authorized age keys
  keys add <key> [name]     Add a recipient key
  keys add-github <user>    Add a recipient by GitHub username
  keys remove <key|#>       Remove a recipient key
`)
}

// --- Keychain ---

func getKey() (string, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-a", os.Getenv("USER"), "-s", keychainService, "-w").Output()
	if err != nil {
		return "", fmt.Errorf("no key in Keychain (run 'shh init')")
	}
	return strings.TrimSpace(string(out)), nil
}

func storeKey(privateKey string) error {
	return exec.Command("security", "add-generic-password",
		"-a", os.Getenv("USER"), "-s", keychainService,
		"-w", privateKey, "-T", "", "-U").Run()
}

func publicKeyFrom(privateKey string) (string, error) {
	cmd := exec.Command("age-keygen", "-y")
	cmd.Stdin = strings.NewReader(privateKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("age-keygen -y: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// --- Key Registry ---

func keyName(pubKey string) string {
	data, err := os.ReadFile(keyRegistryFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, pubKey) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

func registerKey(pubKey, name string) error {
	// Read existing, remove old entry for this key
	var lines []string
	if data, err := os.ReadFile(keyRegistryFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line != "" && !strings.Contains(line, pubKey) {
				lines = append(lines, line)
			}
		}
	}
	lines = append(lines, pubKey+" "+name)
	return os.WriteFile(keyRegistryFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// --- SOPS helpers ---

func sopsKeysFromConfig() ([]string, error) {
	data, err := os.ReadFile(sopsConfigFile)
	if err != nil {
		return nil, fmt.Errorf("no %s found", sopsConfigFile)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- age:") || strings.HasPrefix(line, "age:") {
			raw := strings.TrimPrefix(line, "- age:")
			raw = strings.TrimPrefix(raw, "age:")
			raw = strings.TrimSpace(raw)
			raw = strings.Trim(raw, "\"")
			return strings.Split(raw, ","), nil
		}
	}
	return nil, fmt.Errorf("no age keys found in %s", sopsConfigFile)
}

func writeSopsConfig(keys []string) error {
	content := fmt.Sprintf("creation_rules:\n  - age: \"%s\"\n", strings.Join(keys, ","))
	return os.WriteFile(sopsConfigFile, []byte(content), 0644)
}

func sopsDecrypt(file string) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("sops", "-d", "--input-type", "dotenv", "--output-type", "dotenv", file)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("sops decrypt: %s", string(ee.Stderr))
		}
		return "", fmt.Errorf("sops decrypt: %w", err)
	}
	return string(out), nil
}

func sopsEncrypt(plaintext, file string) error {
	key, err := getKey()
	if err != nil {
		return err
	}
	cmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", "/dev/stdin")
	cmd.Stdin = strings.NewReader(plaintext)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("sops encrypt: %s", string(ee.Stderr))
		}
		return fmt.Errorf("sops encrypt: %w", err)
	}
	return os.WriteFile(file, out, 0644)
}

func sopsUpdateKeys(file string) error {
	key, err := getKey()
	if err != nil {
		return err
	}
	cmd := exec.Command("sops", "updatekeys", "--input-type", "dotenv", file, "-y")
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// --- Dotenv helpers ---

func parseDotenv(content string) []string {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func dotenvGet(lines []string, key string) (int, bool) {
	prefix := key + "="
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return i, true
		}
	}
	return -1, false
}

// --- Commands ---

func cmdInit(args []string) error {
	if err := checkDep("age-keygen", "brew install age"); err != nil {
		return err
	}
	if err := checkDep("sops", "brew install sops"); err != nil {
		return err
	}

	// Already initialized?
	if key, err := getKey(); err == nil {
		pubKey, err := publicKeyFrom(key)
		if err != nil {
			return err
		}
		fmt.Println("Already initialized. Your public key:")
		fmt.Printf("  %s\n", pubKey)
		return nil
	}

	var privateKey, publicKey string

	if len(args) > 0 && args[0] == "--from-ssh" {
		if err := checkDep("ssh-to-age", "go install github.com/Mic92/ssh-to-age/cmd/ssh-to-age@latest"); err != nil {
			return err
		}
		sshKey := filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519")
		if len(args) > 1 {
			sshKey = args[1]
		}
		if _, err := os.Stat(sshKey); err != nil {
			return fmt.Errorf("SSH key not found: %s", sshKey)
		}
		out, err := exec.Command("ssh-to-age", "-private-key", "-i", sshKey).Output()
		if err != nil {
			return fmt.Errorf("ssh-to-age: %w", err)
		}
		privateKey = strings.TrimSpace(string(out))
		publicKey, err = publicKeyFrom(privateKey)
		if err != nil {
			return err
		}
	} else {
		out, err := exec.Command("age-keygen").CombinedOutput()
		if err != nil {
			return fmt.Errorf("age-keygen: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "public key:") {
				parts := strings.Fields(line)
				publicKey = parts[len(parts)-1]
			}
			if strings.HasPrefix(line, "AGE-SECRET-KEY") {
				privateKey = line
			}
		}
	}

	if err := storeKey(privateKey); err != nil {
		return fmt.Errorf("keychain store: %w", err)
	}

	user := os.Getenv("USER")
	registerKey(publicKey, user)

	fmt.Println("Age key stored in macOS Keychain.")
	fmt.Println()
	fmt.Println("Your public key:")
	fmt.Printf("  %s\n", publicKey)
	fmt.Println()
	fmt.Printf("To add you to a project: shh keys add %s %s\n", publicKey, user)
	return nil
}

func cmdEncrypt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh encrypt <file>")
	}
	src := args[0]
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("file not found: %s", src)
	}

	key, err := getKey()
	if err != nil {
		return err
	}
	pubKey, err := publicKeyFrom(key)
	if err != nil {
		return err
	}

	// Create .sops.yaml if it doesn't exist
	if _, err := os.Stat(sopsConfigFile); os.IsNotExist(err) {
		if err := writeSopsConfig([]string{pubKey}); err != nil {
			return err
		}
		registerKey(pubKey, os.Getenv("USER"))
	}

	dest := src + ".enc"
	cmd := exec.Command("sops", "-e", "--input-type", "dotenv", "--output-type", "dotenv", src)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("sops: %s", string(ee.Stderr))
		}
		return fmt.Errorf("sops: %w", err)
	}
	if err := os.WriteFile(dest, out, 0644); err != nil {
		return err
	}
	fmt.Printf("Encrypted %s → %s\n", src, dest)
	fmt.Printf("You can now delete %s.\n", src)
	return nil
}

func cmdDecrypt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh decrypt <file>")
	}
	plaintext, err := sopsDecrypt(args[0])
	if err != nil {
		return err
	}
	fmt.Print(plaintext)
	return nil
}

func cmdEdit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh edit <file>")
	}
	key, err := getKey()
	if err != nil {
		return err
	}
	cmd := exec.Command("sops", "--input-type", "dotenv", "--output-type", "dotenv", args[0])
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+key)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func cmdSet(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: shh set <file> <KEY> <VALUE>")
	}
	file, key, value := args[0], args[1], args[2]

	plaintext, err := sopsDecrypt(file)
	if err != nil {
		return err
	}

	lines := parseDotenv(plaintext)
	newLine := key + "=" + value

	if idx, found := dotenvGet(lines, key); found {
		lines[idx] = newLine
		fmt.Printf("Updated %s in %s.\n", key, file)
	} else {
		lines = append(lines, newLine)
		fmt.Printf("Added %s to %s.\n", key, file)
	}

	return sopsEncrypt(strings.Join(lines, "\n")+"\n", file)
}

func cmdRm(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: shh rm <file> <KEY>")
	}
	file, key := args[0], args[1]

	plaintext, err := sopsDecrypt(file)
	if err != nil {
		return err
	}

	lines := parseDotenv(plaintext)
	if _, found := dotenvGet(lines, key); !found {
		return fmt.Errorf("key %q not found in %s", key, file)
	}

	var filtered []string
	prefix := key + "="
	for _, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			filtered = append(filtered, line)
		}
	}

	if err := sopsEncrypt(strings.Join(filtered, "\n")+"\n", file); err != nil {
		return err
	}
	fmt.Printf("Removed %s from %s.\n", key, file)
	return nil
}

func cmdShell(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh shell <file>")
	}

	plaintext, err := sopsDecrypt(args[0])
	if err != nil {
		return err
	}

	env := os.Environ()
	scanner := bufio.NewScanner(strings.NewReader(plaintext))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		env = append(env, line)
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Println("Secrets loaded. Type 'exit' to end session.")
	return syscall.Exec(shell, []string{shell}, env)
}

func cmdKeys(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return keysListCmd()
	case "add":
		return keysAddCmd(args[1:])
	case "add-github":
		return keysAddGithubCmd(args[1:])
	case "remove":
		return keysRemoveCmd(args[1:])
	default:
		return fmt.Errorf("usage: shh keys <list|add|add-github|remove>")
	}
}

func keysListCmd() error {
	keys, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	var myKey string
	if priv, err := getKey(); err == nil {
		myKey, _ = publicKeyFrom(priv)
	}

	fmt.Println("Authorized keys:")
	for i, key := range keys {
		name := keyName(key)
		marker := ""
		if key == myKey {
			marker = " (you)"
		}
		if name == "" {
			name = "<unnamed>"
		}
		fmt.Printf("  %d. %s  %s%s\n", i+1, key, name, marker)
	}
	return nil
}

func keysAddCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh keys add <age-public-key> [name]")
	}
	newKey := args[0]
	name := ""
	if len(args) > 1 {
		name = args[1]
	}

	if !strings.HasPrefix(newKey, "age1") {
		return fmt.Errorf("expected an age public key starting with 'age1'")
	}

	keys, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	for _, k := range keys {
		if k == newKey {
			fmt.Println("Key already present.")
			return nil
		}
	}

	keys = append(keys, newKey)
	if err := writeSopsConfig(keys); err != nil {
		return err
	}
	if name != "" {
		registerKey(newKey, name)
	}
	fmt.Printf("Added key to %s.\n", sopsConfigFile)

	// Re-encrypt if encrypted file exists
	encFile := ".env.enc"
	if _, err := os.Stat(encFile); err == nil {
		if err := sopsUpdateKeys(encFile); err != nil {
			return fmt.Errorf("re-encrypt: %w", err)
		}
		fmt.Println("Re-encrypted with all keys.")
	}
	return nil
}

func keysAddGithubCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh keys add-github <github-username>")
	}
	username := args[0]

	if err := checkDep("ssh-to-age", "go install github.com/Mic92/ssh-to-age/cmd/ssh-to-age@latest"); err != nil {
		return err
	}

	fmt.Printf("Fetching SSH keys for github.com/%s...\n", username)
	resp, err := http.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return fmt.Errorf("fetch keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("could not fetch keys for %q (HTTP %d)", username, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var ed25519Line string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ssh-ed25519") {
			ed25519Line = line
			break
		}
	}
	if ed25519Line == "" {
		return fmt.Errorf("no ed25519 SSH key found for %q (age requires ed25519)", username)
	}

	cmd := exec.Command("ssh-to-age")
	cmd.Stdin = strings.NewReader(ed25519Line)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("ssh-to-age: %w", err)
	}
	ageKey := strings.TrimSpace(string(out))
	fmt.Printf("Converted %s's SSH key → %s\n", username, ageKey)

	return keysAddCmd([]string{ageKey, username})
}

func keysRemoveCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: shh keys remove <age-public-key or number>")
	}
	target := args[0]

	keys, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	// Resolve number to key
	if n, err := strconv.Atoi(target); err == nil {
		if n < 1 || n > len(keys) {
			return fmt.Errorf("invalid key number: %d", n)
		}
		target = keys[n-1]
	}

	var remaining []string
	found := false
	for _, k := range keys {
		if k == target {
			found = true
		} else {
			remaining = append(remaining, k)
		}
	}
	if !found {
		return fmt.Errorf("key not found: %s", target)
	}
	if len(remaining) == 0 {
		return fmt.Errorf("cannot remove the last key")
	}

	if err := writeSopsConfig(remaining); err != nil {
		return err
	}

	// Remove from registry
	if data, err := os.ReadFile(keyRegistryFile); err == nil {
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			if line != "" && !strings.Contains(line, target) {
				lines = append(lines, line)
			}
		}
		os.WriteFile(keyRegistryFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	}

	fmt.Printf("Removed key: %s\n", target)

	encFile := ".env.enc"
	if _, err := os.Stat(encFile); err == nil {
		if err := sopsUpdateKeys(encFile); err != nil {
			return fmt.Errorf("re-encrypt: %w", err)
		}
		fmt.Println("Re-encrypted.")
	}
	return nil
}

// --- Helpers ---

func checkDep(name, installHint string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found. Install: %s", name, installHint)
	}
	return nil
}


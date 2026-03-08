package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
	sshtoa "github.com/Mic92/ssh-to-age"
	"github.com/charmbracelet/lipgloss"
	"github.com/cockroachdb/errors"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/spf13/cobra"
)

const (
	keychainService    = "shh-age-key"
	sopsConfigFile     = ".sops.yaml"
	keyRegistryFile    = ".age-keys"
	defaultEncryptedFile = ".env.enc"
)

// --- Lipgloss Styles ---

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true).Underline(true)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	nameStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	youStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	hintStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true)

	// Validation patterns
	ageKeyPattern     = regexp.MustCompile(`^age1[a-z0-9]{58}$`)
	githubUserPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

	// HTTP client with timeout and no redirects to untrusted hosts
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != "github.com" {
				return errors.Newf("refusing redirect to %s", req.URL.Host)
			}
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	// Maximum response size for fetching keys (1MB)
	maxResponseSize int64 = 1 << 20
)

// --- Cobra Commands ---

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "shh",
		Short: "Encrypted .env management with age+sops+Keychain",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate age key and store in Keychain",
		RunE:  runInit,
	}
	initCmd.Flags().String("from-ssh", "", "Derive age key from SSH ed25519 key (optionally specify path)")
	rootCmd.AddCommand(initCmd)

	// encrypt command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a .env file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdEncrypt(args[0])
		},
	})

	// decrypt command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "decrypt [file]",
		Short: "Print decrypted contents",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdDecrypt(fileArg(args))
		},
	})

	// edit command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "edit [file]",
		Short: "Edit secrets in $EDITOR",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdEdit(fileArg(args))
		},
	})

	// set command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "set <KEY> <VALUE> [file]",
		Short: "Add or update a secret",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := defaultEncryptedFile
			if len(args) > 2 {
				file = args[2]
			}
			return cmdSet(file, args[0], args[1])
		},
	})

	// rm command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "rm <KEY> [file]",
		Short: "Remove a secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := defaultEncryptedFile
			if len(args) > 1 {
				file = args[1]
			}
			return cmdRm(file, args[0])
		},
	})

	// shell command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "shell [file]",
		Short: "Start a subshell with secrets loaded",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdShell(fileArg(args))
		},
	})

	// keys command with subcommands
	keysCmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage authorized age keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return keysListCmd()
		},
	}

	keysCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List authorized age keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return keysListCmd()
		},
	})

	keysCmd.AddCommand(&cobra.Command{
		Use:   "add <key> [name]",
		Short: "Add a recipient key",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return keysAddCmd(args)
		},
	})

	keysCmd.AddCommand(&cobra.Command{
		Use:   "add-github <user>",
		Short: "Add a recipient by GitHub username",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return keysAddGithubCmd(args)
		},
	})

	keysCmd.AddCommand(&cobra.Command{
		Use:   "remove <key|#>",
		Short: "Remove a recipient key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return keysRemoveCmd(args)
		},
	})

	rootCmd.AddCommand(keysCmd)

	return rootCmd
}

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, errorStyle.Render("error: "+err.Error()))
		os.Exit(1)
	}
}

// --- Helpers ---

func fileArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return defaultEncryptedFile
}

func currentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

// --- Keyring ---

func getKey() (string, error) {
	// Allow env var override (for CI, Docker, headless environments)
	if key := os.Getenv("SHH_AGE_KEY"); key != "" {
		return key, nil
	}
	key, err := keyring.Get(keychainService, currentUsername())
	if err != nil {
		return "", errors.New("no key found (run 'shh init')")
	}
	return key, nil
}

func storeKey(privateKey string) error {
	return keyring.Set(keychainService, currentUsername(), privateKey)
}

func publicKeyFrom(privateKey string) (string, error) {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "parse age identity")
	}
	return identity.Recipient().String(), nil
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
	// Sanitize name: no newlines or control characters
	name = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 32 {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)

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
		return nil, errors.Newf("no %s found", sopsConfigFile)
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
	return nil, errors.Newf("no age keys found in %s", sopsConfigFile)
}

func writeSopsConfig(keys []string) error {
	content := fmt.Sprintf("creation_rules:\n  - age: \"%s\"\n", strings.Join(keys, ","))
	return os.WriteFile(sopsConfigFile, []byte(content), 0644)
}

// setAgeKeyEnv sets the SOPS_AGE_KEY environment variable for sops library operations.
// If the env var is already set (e.g. in tests), it is left untouched.
func setAgeKeyEnv() (cleanup func(), err error) {
	if os.Getenv(sopsage.SopsAgeKeyEnv) != "" {
		return func() {}, nil
	}
	key, err := getKey()
	if err != nil {
		return nil, err
	}
	os.Setenv(sopsage.SopsAgeKeyEnv, key)
	return func() { os.Unsetenv(sopsage.SopsAgeKeyEnv) }, nil
}

func newDotenvStore() *dotenv.Store {
	return &dotenv.Store{}
}

func sopsDecrypt(file string) (string, error) {
	cleanup, err := setAgeKeyEnv()
	if err != nil {
		return "", err
	}
	defer cleanup()

	data, err := os.ReadFile(file)
	if err != nil {
		return "", errors.Wrap(err, "read file")
	}

	store := newDotenvStore()
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return "", errors.Wrap(err, "sops load encrypted file")
	}

	dataKey, err := tree.Metadata.GetDataKey()
	if err != nil {
		return "", errors.Wrap(err, "sops get data key")
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return "", errors.Wrap(err, "sops decrypt")
	}

	// Verify MAC
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return "", errors.Wrap(err, "sops decrypt MAC")
	}
	if originalMac != mac {
		return "", errors.Newf("MAC mismatch: expected %q, got %q", originalMac, mac)
	}

	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return "", errors.Wrap(err, "sops emit plain file")
	}
	return string(plaintext), nil
}

func sopsEncrypt(plaintext, file string) error {
	cleanup, err := setAgeKeyEnv()
	if err != nil {
		return err
	}
	defer cleanup()

	store := newDotenvStore()
	branches, err := store.LoadPlainFile([]byte(plaintext))
	if err != nil {
		return errors.Wrap(err, "parse dotenv")
	}

	// Read recipients from .sops.yaml
	recipients, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	// Create age master keys
	var ageKeys sops.KeyGroup
	for _, r := range recipients {
		mk, err := sopsage.MasterKeyFromRecipient(r)
		if err != nil {
			return errors.Wrapf(err, "parse recipient %s", r)
		}
		ageKeys = append(ageKeys, mk)
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{ageKeys},
			Version:   "3.9.0",
		},
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	)
	if len(errs) > 0 {
		return errors.Wrap(errs[0], "generate data key")
	}

	cipher := aes.NewCipher()
	unencryptedMac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return errors.Wrap(err, "encrypt tree")
	}

	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		unencryptedMac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return errors.Wrap(err, "encrypt MAC")
	}

	output, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return errors.Wrap(err, "emit encrypted file")
	}

	return os.WriteFile(file, output, 0600)
}

func sopsUpdateKeys(file string) error {
	cleanup, err := setAgeKeyEnv()
	if err != nil {
		return err
	}
	defer cleanup()

	store := newDotenvStore()

	data, err := os.ReadFile(file)
	if err != nil {
		return errors.Wrap(err, "read file")
	}
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return errors.Wrap(err, "load encrypted file")
	}

	// Read new recipients from .sops.yaml
	recipients, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	// Create new key groups
	var ageKeys sops.KeyGroup
	for _, r := range recipients {
		mk, err := sopsage.MasterKeyFromRecipient(r)
		if err != nil {
			return errors.Wrapf(err, "parse recipient %s", r)
		}
		ageKeys = append(ageKeys, mk)
	}

	// Get the data key using current master keys
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()},
		nil,
	)
	if err != nil {
		return errors.Wrap(err, "get data key")
	}

	// Update to new key groups and re-encrypt the data key
	tree.Metadata.KeyGroups = []sops.KeyGroup{ageKeys}
	updateErrs := tree.Metadata.UpdateMasterKeysWithKeyServices(
		dataKey,
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	)
	if len(updateErrs) > 0 {
		return errors.Wrap(updateErrs[0], "update master keys")
	}

	output, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return errors.Wrap(err, "emit encrypted file")
	}

	return os.WriteFile(file, output, 0600)
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

func runInit(cmd *cobra.Command, args []string) error {
	// Already initialized?
	if key, err := getKey(); err == nil {
		pubKey, err := publicKeyFrom(key)
		if err != nil {
			return err
		}
		fmt.Println("Already initialized. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	var privateKey, publicKey string

	fromSSH, _ := cmd.Flags().GetString("from-ssh")
	if cmd.Flags().Changed("from-ssh") {
		sshKey := fromSSH
		if sshKey == "" {
			sshKey = filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519")
		}
		if _, err := os.Stat(sshKey); err != nil {
			return errors.Newf("SSH key not found: %s", sshKey)
		}
		sshKeyData, err := os.ReadFile(sshKey)
		if err != nil {
			return errors.Wrap(err, "read SSH key")
		}
		privKeyPtr, pubKeyPtr, err := sshtoa.SSHPrivateKeyToAge(sshKeyData, nil)
		if err != nil {
			return errors.Wrap(err, "ssh-to-age")
		}
		privateKey = *privKeyPtr
		publicKey = *pubKeyPtr
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return errors.Wrap(err, "generate age key")
		}
		privateKey = identity.String()
		publicKey = identity.Recipient().String()
	}

	if err := storeKey(privateKey); err != nil {
		return errors.Wrap(err, "keychain store")
	}

	username := currentUsername()
	registerKey(publicKey, username)

	fmt.Println(successStyle.Render("Age key stored in macOS Keychain."))
	fmt.Println()
	fmt.Println("Your public key:")
	fmt.Printf("  %s\n", keyStyle.Render(publicKey))
	fmt.Println()
	fmt.Printf("To add you to a project: shh keys add %s %s\n", publicKey, username)
	return nil
}

func cmdEncrypt(src string) error {
	if _, err := os.Stat(src); err != nil {
		return errors.Newf("file not found: %s", src)
	}

	if err := ensureSopsConfig(); err != nil {
		return err
	}

	// Read the source file and encrypt it
	plaintext, err := os.ReadFile(src)
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	dest := src + ".enc"
	if err := sopsEncrypt(string(plaintext), dest); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Encrypted %s -> %s", src, dest)))
	fmt.Printf("You can now delete %s.\n", src)
	return nil
}

func cmdDecrypt(file string) error {
	plaintext, err := sopsDecrypt(file)
	if err != nil {
		return err
	}
	fmt.Print(plaintext)
	return nil
}

func ensureSopsConfig() error {
	if _, err := os.Stat(sopsConfigFile); os.IsNotExist(err) {
		key, err := getKey()
		if err != nil {
			return err
		}
		pubKey, err := publicKeyFrom(key)
		if err != nil {
			return err
		}
		if err := writeSopsConfig([]string{pubKey}); err != nil {
			return err
		}
		registerKey(pubKey, currentUsername())
	}
	return nil
}

func cmdEdit(file string) error {

	// Decrypt existing file, or start empty for new files
	var plaintext string
	if _, err := os.Stat(file); err == nil {
		plaintext, err = sopsDecrypt(file)
		if err != nil {
			return err
		}
	}

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "shh-edit-*.env")
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(plaintext); err != nil {
		tmpFile.Close()
		return errors.Wrap(err, "write temp file")
	}
	tmpFile.Close()

	// Get file info for modification time check
	infoBefore, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}

	// Open $EDITOR
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return errors.Wrap(err, "editor")
	}

	// Check if the file was modified
	infoAfter, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		fmt.Println("No changes made.")
		return nil
	}

	// Re-read and re-encrypt
	edited, err := os.ReadFile(tmpPath)
	if err != nil {
		return errors.Wrap(err, "read edited file")
	}

	if err := ensureSopsConfig(); err != nil {
		return err
	}
	return sopsEncrypt(string(edited), file)
}

func cmdSet(file, key, value string) error {

	var plaintext string
	if _, err := os.Stat(file); err == nil {
		var decErr error
		plaintext, decErr = sopsDecrypt(file)
		if decErr != nil {
			return decErr
		}
	}

	if err := ensureSopsConfig(); err != nil {
		return err
	}

	lines := parseDotenv(plaintext)
	newLine := key + "=" + value

	if idx, found := dotenvGet(lines, key); found {
		lines[idx] = newLine
		fmt.Println(successStyle.Render(fmt.Sprintf("Updated %s in %s.", key, file)))
	} else {
		lines = append(lines, newLine)
		fmt.Println(successStyle.Render(fmt.Sprintf("Added %s to %s.", key, file)))
	}

	return sopsEncrypt(strings.Join(lines, "\n")+"\n", file)
}

func cmdRm(file, key string) error {

	plaintext, err := sopsDecrypt(file)
	if err != nil {
		return err
	}

	lines := parseDotenv(plaintext)
	if _, found := dotenvGet(lines, key); !found {
		return errors.Newf("key %q not found in %s", key, file)
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
	fmt.Println(successStyle.Render(fmt.Sprintf("Removed %s from %s.", key, file)))
	return nil
}

func cmdShell(file string) error {
	plaintext, err := sopsDecrypt(file)
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

	fmt.Println(successStyle.Render("Secrets loaded.") + " Type 'exit' to end session.")
	return syscall.Exec(shell, []string{shell}, env)
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

	fmt.Println(headerStyle.Render("Authorized keys"))
	for i, key := range keys {
		name := keyName(key)
		marker := ""
		if key == myKey {
			marker = " " + youStyle.Render("(you)")
		}
		if name == "" {
			name = hintStyle.Render("<unnamed>")
		} else {
			name = nameStyle.Render(name)
		}
		fmt.Printf("  %d. %s  %s%s\n", i+1, keyStyle.Render(key), name, marker)
	}
	return nil
}

func keysAddCmd(args []string) error {
	newKey := args[0]
	name := ""
	if len(args) > 1 {
		name = args[1]
	}

	if !ageKeyPattern.MatchString(newKey) {
		return errors.New("invalid age public key (expected age1 followed by 58 lowercase alphanumeric characters)")
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
	fmt.Println(successStyle.Render(fmt.Sprintf("Added key to %s.", sopsConfigFile)))

	// Re-encrypt if encrypted file exists
	encFile := defaultEncryptedFile
	if _, err := os.Stat(encFile); err == nil {
		if err := sopsUpdateKeys(encFile); err != nil {
			return errors.Wrap(err, "re-encrypt")
		}
		fmt.Println(successStyle.Render("Re-encrypted with all keys."))
	}
	return nil
}

func keysAddGithubCmd(args []string) error {
	username := args[0]

	if !githubUserPattern.MatchString(username) {
		return errors.Newf("invalid GitHub username: %q", username)
	}

	fmt.Printf("Fetching SSH keys for github.com/%s...\n", username)
	resp, err := httpClient.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return errors.Wrap(err, "fetch keys")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.Newf("could not fetch keys for %q (HTTP %d)", username, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
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
		return errors.Newf("no ed25519 SSH key found for %q (age requires ed25519)", username)
	}

	ageKeyPtr, err := sshtoa.SSHPublicKeyToAge([]byte(ed25519Line))
	if err != nil {
		return errors.Wrap(err, "ssh-to-age")
	}
	ageKey := *ageKeyPtr
	fmt.Printf("Converted %s's SSH key -> %s\n", username, keyStyle.Render(ageKey))

	return keysAddCmd([]string{ageKey, username})
}

func keysRemoveCmd(args []string) error {
	target := args[0]

	keys, err := sopsKeysFromConfig()
	if err != nil {
		return err
	}

	// Resolve number to key
	if n, err := strconv.Atoi(target); err == nil {
		if n < 1 || n > len(keys) {
			return errors.Newf("invalid key number: %d", n)
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
		return errors.Newf("key not found: %s", target)
	}
	if len(remaining) == 0 {
		return errors.New("cannot remove the last key")
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

	fmt.Println(successStyle.Render(fmt.Sprintf("Removed key: %s", target)))

	encFile := defaultEncryptedFile
	if _, err := os.Stat(encFile); err == nil {
		if err := sopsUpdateKeys(encFile); err != nil {
			return errors.Wrap(err, "re-encrypt")
		}
		fmt.Println(successStyle.Render("Re-encrypted."))
	}
	return nil
}

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	sshtoa "github.com/Mic92/ssh-to-age"
	"github.com/BurntSushi/toml"
	"github.com/charmbracelet/lipgloss"
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	keychainService      = "shh-age-key"
	defaultEncryptedFile = ".env.enc"
	fileVersion          = 1
)

// --- Lipgloss Styles ---

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true).Underline(true)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	nameStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	youStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	hintStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true)

	// Validation patterns
	ageKeyPattern     = regexp.MustCompile(`^age1[a-z0-9]{58}$`)
	githubUserPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	envVarKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// Dangerous env vars that could hijack execution if set via secrets
	dangerousEnvVars = map[string]bool{
		"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
	}

	// HTTP client with timeout and no redirects to untrusted hosts
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "github.com" {
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

// --- Encrypted File Format ---

type EncryptedFile struct {
	Version    int               `toml:"version"`
	MAC        string            `toml:"mac"`
	DataKey    string            `toml:"data_key"`
	Recipients map[string]string `toml:"recipients"`
	Secrets    map[string]string `toml:"secrets"`
}

// --- Cobra Commands ---

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "shh",
		Short: "Encrypted .env management with age encryption",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate age key and store in OS keyring",
		RunE:  runInit,
	}
	rootCmd.AddCommand(initCmd)

	// login command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "login",
		Short: "Log in (auto-detects SSH key via GitHub)",
		RunE:  runLogin,
	})

	// whoami command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show your public key and recipient name",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdWhoami()
		},
	})

	// logout command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "logout",
		Short: "Remove age key from OS keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdLogout()
		},
	})

	// encrypt command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a .env file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdEncrypt(args[0])
		},
	})

	// list command
	listCmd := &cobra.Command{
		Use:   "list [file]",
		Short: "List secret keys (names only, no values)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			return cmdList(resolveFile(env, args))
		},
	}
	listCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(listCmd)

	// env command
	envCmd := &cobra.Command{
		Use:   "env [file]",
		Short: "Print secrets as export statements",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			quiet, _ := cmd.Flags().GetBool("quiet")
			return cmdEnv(resolveFile(env, args), os.Stderr, func() bool {
				return term.IsTerminal(int(os.Stdout.Fd()))
			}, quiet)
		},
	}
	envCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	envCmd.Flags().BoolP("quiet", "q", false, "Suppress non-TTY warning")
	rootCmd.AddCommand(envCmd)

	// edit command
	editCmd := &cobra.Command{
		Use:   "edit [file]",
		Short: "Edit secrets in $EDITOR",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			return cmdEdit(resolveFile(env, args))
		},
	}
	editCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(editCmd)

	// set command
	setCmd := &cobra.Command{
		Use:   "set <KEY> <VALUE> [file]",
		Short: "Add or update a secret",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			file := resolveFile(env, nil)
			if len(args) > 2 {
				file = args[2]
			}
			return cmdSet(file, args[0], args[1])
		},
	}
	setCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(setCmd)

	// rm command
	rmCmd := &cobra.Command{
		Use:     "rm <KEY> [file]",
		Aliases: []string{"unset"},
		Short:   "Remove a secret",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			file := resolveFile(env, nil)
			if len(args) > 1 {
				file = args[1]
			}
			return cmdRm(file, args[0])
		},
	}
	rmCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(rmCmd)

	// shell command
	shellCmd := &cobra.Command{
		Use:     "shell [file]",
		Aliases: []string{"sh"},
		Short:   "Start a subshell with secrets loaded",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			return cmdShell(resolveFile(env, args))
		},
	}
	shellCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(shellCmd)

	// run command
	runCmd := &cobra.Command{
		Use:                "run [file] -- <command> [args...]",
		Short:              "Run a command with secrets in the environment",
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, cmdArgs := parseRunArgs(args)
			if len(cmdArgs) == 0 {
				return errors.New("usage: shh run [file] -- <command> [args...]")
			}
			return cmdRun(file, cmdArgs)
		},
	}
	rootCmd.AddCommand(runCmd)

	// doctor command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check your shh setup for common issues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdDoctor()
		},
	})

	// users command with subcommands
	usersCmd := &cobra.Command{
		Use:   "users",
		Short: "Manage authorized users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return usersListCmd()
		},
	}

	usersCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List authorized users",
		RunE: func(cmd *cobra.Command, args []string) error {
			return usersListCmd()
		},
	})

	usersCmd.AddCommand(&cobra.Command{
		Use:   "add <github-username | age-public-key>",
		Short: "Add a user by GitHub username or age public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return usersAddCmd(args)
		},
	})

	usersCmd.AddCommand(&cobra.Command{
		Use:     "remove <user|#>",
		Aliases: []string{"rm"},
		Short:   "Remove a user",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return usersRemoveCmd(args)
		},
	})

	rootCmd.AddCommand(usersCmd)

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

// findEncFile walks up from the current directory looking for .env.enc.
// Returns the path if found, otherwise falls back to defaultEncryptedFile
// in the current directory (so that create operations still work).
func findEncFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return defaultEncryptedFile
	}
	for {
		candidate := filepath.Join(dir, defaultEncryptedFile)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return defaultEncryptedFile
}

func fileArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return findEncFile()
}

func envFlag(envName string) string {
	if envName == "" {
		return ""
	}
	return envName + ".env.enc"
}

func resolveFile(envName string, args []string) string {
	if envName != "" {
		return envFlag(envName)
	}
	return fileArg(args)
}

func currentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

func requireGHUsername() (string, error) {
	username := ghUsername()
	if username == "" {
		return "", errors.New("GitHub CLI (gh) is required but not installed or not logged in.\n\n  Install: https://cli.github.com\n  Then:    gh auth login")
	}
	return username, nil
}

// recipientDisplayName returns a short display name for a recipient.
func recipientDisplayName(name string) string {
	if strings.HasPrefix(name, "https://github.com/") {
		return strings.TrimPrefix(name, "https://github.com/")
	}
	return name
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func filterEnv(env []string, remove ...string) []string {
	var filtered []string
	for _, e := range env {
		skip := false
		for _, r := range remove {
			if strings.HasPrefix(e, r+"=") {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// --- Keyring ---

func cmdWhoami() error {
	privKey, err := getKey()
	if err != nil {
		return errors.New("not logged in (run 'shh init' or 'shh login')")
	}
	pubKey, err := publicKeyFrom(privKey)
	if err != nil {
		return err
	}

	fmt.Printf("  key: %s\n", keyStyle.Render(pubKey))

	// Check if we're in a project's recipients list
	if ef, err := loadEncryptedFile(findEncFile()); err == nil {
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				fmt.Printf(" user: %s\n", nameStyle.Render(name))
				break
			}
		}
	}

	// Check which SSH key this corresponds to
	for _, sshPath := range findSSHEd25519Keys() {
		data, err := os.ReadFile(sshPath)
		if err != nil {
			continue
		}
		_, pubPtr, err := sshKeyToAge(data, sshPath)
		if err != nil {
			continue
		}
		if *pubPtr == pubKey {
			fmt.Printf("  ssh: %s\n", hintStyle.Render(sshPath))
			break
		}
	}

	return nil
}

func cmdLogout() error {
	err := keyring.Delete(keychainService, currentUsername())
	if err != nil {
		return errors.New("no key found in keyring")
	}
	fmt.Println(successStyle.Render("Age key removed from OS keyring."))
	return nil
}

func getKey() (string, error) {
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

// --- Crypto Layer ---

func generateDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.Wrap(err, "generate data key")
	}
	return key, nil
}

func encryptValue(dataKey []byte, keyName string, plaintext string) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", errors.Wrap(err, "create cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "create GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "generate nonce")
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(keyName))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptValue(dataKey []byte, keyName string, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.Wrap(err, "base64 decode")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", errors.Wrap(err, "create cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "create GCM")
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], []byte(keyName))
	if err != nil {
		return "", errors.Wrap(err, "decrypt")
	}
	return string(plaintext), nil
}

func wrapDataKey(dataKey []byte, recipientKeys []string) (string, error) {
	var recipients []age.Recipient
	for _, r := range recipientKeys {
		rec, err := age.ParseX25519Recipient(r)
		if err != nil {
			return "", errors.Wrapf(err, "parse recipient %s", r)
		}
		recipients = append(recipients, rec)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return "", errors.Wrap(err, "age encrypt")
	}
	if _, err := w.Write(dataKey); err != nil {
		return "", errors.Wrap(err, "write data key")
	}
	if err := w.Close(); err != nil {
		return "", errors.Wrap(err, "close age writer")
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func unwrapDataKey(wrapped string, privateKey string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode data key")
	}
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "parse age identity")
	}
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, errors.Wrap(err, "age decrypt data key")
	}
	return io.ReadAll(r)
}

// computeMAC computes HMAC-SHA256 over all file fields: version, wrapped data key,
// recipients, and encrypted secrets. This prevents tampering with any field.
func computeMAC(dataKey []byte, version int, wrappedDataKey string, recipients map[string]string, secrets map[string]string) string {
	mac := hmac.New(sha256.New, dataKey)
	fmt.Fprintf(mac, "version:%d\x00", version)
	mac.Write([]byte("data_key:"))
	mac.Write([]byte(wrappedDataKey))
	mac.Write([]byte{0})
	for _, name := range sortedKeys(recipients) {
		mac.Write([]byte("recipient:"))
		mac.Write([]byte(name))
		mac.Write([]byte{0})
		mac.Write([]byte(recipients[name]))
		mac.Write([]byte{0})
	}
	for _, k := range sortedKeys(secrets) {
		mac.Write([]byte(k))
		mac.Write([]byte{0})
		mac.Write([]byte(secrets[k]))
		mac.Write([]byte{0})
	}
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// --- File I/O ---

func loadEncryptedFile(path string) (*EncryptedFile, error) {
	var ef EncryptedFile
	if _, err := toml.DecodeFile(path, &ef); err != nil {
		return nil, errors.Wrap(err, "parse encrypted file")
	}
	if ef.Version != fileVersion {
		return nil, errors.Newf("unsupported file version: %d (expected %d)", ef.Version, fileVersion)
	}
	if ef.Recipients == nil {
		ef.Recipients = make(map[string]string)
	}
	if ef.Secrets == nil {
		ef.Secrets = make(map[string]string)
	}
	return &ef, nil
}

func tomlKey(s string) string {
	if s == "" {
		return `""`
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return fmt.Sprintf("%q", s)
		}
	}
	return s
}

func validateTOMLValue(s string) error {
	for i, c := range s {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return errors.Newf("value contains control character at position %d (U+%04X)", i, c)
		}
	}
	return nil
}

func marshalEncryptedFile(ef *EncryptedFile) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "version = %d\n", ef.Version)
	fmt.Fprintf(&buf, "mac = %q\n", ef.MAC)
	fmt.Fprintf(&buf, "data_key = %q\n", ef.DataKey)

	buf.WriteString("\n[recipients]\n")
	for _, name := range sortedKeys(ef.Recipients) {
		if err := validateTOMLValue(ef.Recipients[name]); err != nil {
			return nil, errors.Wrapf(err, "recipient %q", name)
		}
		fmt.Fprintf(&buf, "%s = %q\n", tomlKey(name), ef.Recipients[name])
	}

	buf.WriteString("\n[secrets]\n")
	for _, k := range sortedKeys(ef.Secrets) {
		if err := validateTOMLValue(ef.Secrets[k]); err != nil {
			return nil, errors.Wrapf(err, "secret %q", k)
		}
		fmt.Fprintf(&buf, "%s = %q\n", tomlKey(k), ef.Secrets[k])
	}

	return buf.Bytes(), nil
}

func saveEncryptedFile(path string, ef *EncryptedFile) error {
	data, err := marshalEncryptedFile(ef)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".shh-*.tmp")
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()      // #nosec G104 -- cleanup in error path; primary error already captured
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup; primary error already captured
		return errors.Wrap(err, "write temp file")
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()      // #nosec G104 -- cleanup in error path; primary error already captured
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup; primary error already captured
		return errors.Wrap(err, "chmod temp file")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup; primary error already captured
		return errors.Wrap(err, "close temp file")
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup; primary error already captured
		return errors.Wrap(err, "rename temp file")
	}
	return nil
}

// --- Encrypt / Decrypt ---

func encryptSecrets(secrets map[string]string, recipients map[string]string) (*EncryptedFile, error) {
	dataKey, err := generateDataKey()
	if err != nil {
		return nil, err
	}

	pubKeys := make([]string, 0, len(recipients))
	for _, pk := range recipients {
		pubKeys = append(pubKeys, pk)
	}
	sort.Strings(pubKeys) // deterministic order for age encryption

	wrappedKey, err := wrapDataKey(dataKey, pubKeys)
	if err != nil {
		return nil, err
	}

	encSecrets := make(map[string]string, len(secrets))
	for k, v := range secrets {
		enc, err := encryptValue(dataKey, k, v)
		if err != nil {
			return nil, errors.Wrapf(err, "encrypt %s", k)
		}
		encSecrets[k] = enc
	}

	mac := computeMAC(dataKey, fileVersion, wrappedKey, recipients, encSecrets)

	return &EncryptedFile{
		Version:    fileVersion,
		MAC:        mac,
		DataKey:    wrappedKey,
		Recipients: recipients,
		Secrets:    encSecrets,
	}, nil
}

func decryptSecrets(ef *EncryptedFile) (map[string]string, error) {
	privKey, err := getKey()
	if err != nil {
		return nil, err
	}

	// Check if our key is in the recipients list
	pubKey, err := publicKeyFrom(privKey)
	if err != nil {
		return nil, err
	}
	found := false
	for _, pk := range ef.Recipients {
		if pk == pubKey {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, 0, len(ef.Recipients))
		for name := range ef.Recipients {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, errors.Newf("your key (%s) is not in the recipients list\n  authorized: %s\n  ask a teammate to run: shh users add <your-github-username>",
			pubKey, strings.Join(names, ", "))
	}

	dataKey, err := unwrapDataKey(ef.DataKey, privKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt data key")
	}

	// Verify MAC
	expected := computeMAC(dataKey, ef.Version, ef.DataKey, ef.Recipients, ef.Secrets)
	if !hmac.Equal([]byte(expected), []byte(ef.MAC)) {
		return nil, errors.New("MAC verification failed — file may be tampered")
	}

	secrets := make(map[string]string, len(ef.Secrets))
	for k, v := range ef.Secrets {
		dec, err := decryptValue(dataKey, k, v)
		if err != nil {
			return nil, errors.Wrapf(err, "decrypt %s", k)
		}
		secrets[k] = dec
	}

	return secrets, nil
}

func reWrapDataKey(ef *EncryptedFile, newRecipients map[string]string) error {
	privKey, err := getKey()
	if err != nil {
		return err
	}

	dataKey, err := unwrapDataKey(ef.DataKey, privKey)
	if err != nil {
		return errors.Wrap(err, "decrypt data key")
	}

	pubKeys := make([]string, 0, len(newRecipients))
	for _, pk := range newRecipients {
		pubKeys = append(pubKeys, pk)
	}
	sort.Strings(pubKeys)

	newWrapped, err := wrapDataKey(dataKey, pubKeys)
	if err != nil {
		return err
	}

	ef.DataKey = newWrapped
	ef.Recipients = newRecipients
	ef.Version = fileVersion
	ef.MAC = computeMAC(dataKey, ef.Version, ef.DataKey, ef.Recipients, ef.Secrets)
	return nil
}

// shellQuote returns a POSIX single-quoted string safe to use in shell output.
// Single-quoting prevents all shell expansion (variables, backticks, globs).
// The only character that must be handled specially is the single-quote itself,
// which is escaped by ending the single-quoted string, emitting a
// backslash-escaped single-quote, then resuming single-quoting.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// --- Plaintext helpers ---

func parsePlaintext(content string) map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx >= 0 {
			m[line[:idx]] = line[idx+1:]
		}
	}
	return m
}

func formatPlaintext(secrets map[string]string) string {
	var buf strings.Builder
	for _, k := range sortedKeys(secrets) {
		fmt.Fprintf(&buf, "%s=%s\n", k, secrets[k])
	}
	return buf.String()
}

func defaultRecipients() (map[string]string, error) {
	privKey, err := getKey()
	if err != nil {
		return nil, err
	}
	pubKey, err := publicKeyFrom(privKey)
	if err != nil {
		return nil, err
	}
	username, err := requireGHUsername()
	if err != nil {
		return nil, err
	}
	return map[string]string{"https://github.com/" + username: pubKey}, nil
}

// loadSecrets loads secrets either from a plaintext file (if SHH_PLAINTEXT is set)
// or by decrypting the encrypted file.
func loadSecrets(encFile string) (map[string]string, error) {
	if plainFile := os.Getenv("SHH_PLAINTEXT"); plainFile != "" {
		data, err := os.ReadFile(plainFile)
		if err != nil {
			return nil, errors.Wrapf(err, "read plaintext file %s", plainFile)
		}
		return parsePlaintext(string(data)), nil
	}

	ef, err := loadEncryptedFile(encFile)
	if err != nil {
		return nil, err
	}
	return decryptSecrets(ef)
}

// --- Commands ---

// ghUsername returns the GitHub username from `gh auth status`, or "" if unavailable.
func ghUsername() string {
	out, err := exec.Command("gh", "auth", "status").CombinedOutput()
	if err != nil {
		return ""
	}
	// Parse "Logged in to github.com account <username>"
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "account") {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "account" && i+1 < len(parts) {
					return strings.TrimRight(parts[i+1], " ()")
				}
			}
		}
	}
	return ""
}

// readPassphrase prompts the user for an SSH key passphrase.
// It is a package-level var so tests can replace it.
var readPassphrase = func(keyPath string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", keyPath)
	pass, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	return pass, err
}

// sshKeyToAge converts an SSH private key to age identity strings,
// prompting for a passphrase if needed.
func sshKeyToAge(data []byte, keyPath string) (*string, *string, error) {
	priv, pub, err := sshtoa.SSHPrivateKeyToAge(data, nil)
	if err == nil {
		return priv, pub, nil
	}

	// Check if passphrase is needed
	var missingErr *ssh.PassphraseMissingError
	if !errors.As(err, &missingErr) {
		return nil, nil, err
	}

	passphrase, err := readPassphrase(keyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read passphrase")
	}

	return sshtoa.SSHPrivateKeyToAge(data, passphrase)
}

// findSSHEd25519Keys returns paths to all ed25519 private keys in ~/.ssh/
func findSSHEd25519Keys() []string {
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(sshDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		// Quick check for SSH private key marker
		if !bytes.Contains(data, []byte("OPENSSH PRIVATE KEY")) {
			continue
		}
		// Try to convert — ssh-to-age will reject non-ed25519
		if _, _, err := sshtoa.SSHPrivateKeyToAge(data, nil); err == nil {
			keys = append(keys, path)
			continue
		}
		// If passphrase-protected, include it — we'll confirm type at conversion time
		_, err = ssh.ParseRawPrivateKey(data)
		var missingErr *ssh.PassphraseMissingError
		if errors.As(err, &missingErr) {
			keys = append(keys, path)
		}
	}
	return keys
}

func runLogin(cmd *cobra.Command, args []string) error {
	if key, err := getKey(); err == nil {
		pubKey, _ := publicKeyFrom(key)
		fmt.Println("Already logged in. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	// Require GitHub CLI
	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	// Load recipients from .env.enc if it exists
	var recipients map[string]string
	if ef, err := loadEncryptedFile(findEncFile()); err == nil {
		recipients = ef.Recipients
	}

	// Find local SSH keys and try to match against recipients
	for _, sshPath := range findSSHEd25519Keys() {
		data, _ := os.ReadFile(sshPath)
		privPtr, pubPtr, err := sshKeyToAge(data, sshPath)
		if err != nil {
			continue
		}
		if recipients != nil {
			for _, rk := range recipients {
				if rk == *pubPtr {
					if err := storeKey(*privPtr); err != nil {
						return errors.Wrap(err, "keyring store")
					}
					fmt.Printf("Matched SSH key %s\n", hintStyle.Render(sshPath))
					fmt.Println(successStyle.Render("Key stored in OS keyring."))
					fmt.Printf("  %s\n", keyStyle.Render(*pubPtr))
					return nil
				}
			}
		}
	}

	if recipients != nil {
		return errors.Newf("your SSH key is not in the recipients list\n  ask a teammate to run: shh users add %s", username)
	}

	return errors.New("no .env.enc found — run 'shh init' to start a new project")
}

func runInit(cmd *cobra.Command, args []string) error {
	if key, err := getKey(); err == nil {
		pubKey, err := publicKeyFrom(key)
		if err != nil {
			return err
		}
		fmt.Println("Already initialized. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	// Require GitHub CLI
	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	var privateKey, publicKey string

	// Try to find an ed25519 SSH key to derive from
	sshKeys := findSSHEd25519Keys()
	if len(sshKeys) > 0 {
		sshKey := sshKeys[0]
		sshKeyData, err := os.ReadFile(sshKey) // #nosec G304 -- auto-detected from ~/.ssh
		if err != nil {
			return errors.Wrap(err, "read SSH key")
		}
		privKeyPtr, pubKeyPtr, err := sshKeyToAge(sshKeyData, sshKey)
		if err != nil {
			return errors.Wrap(err, "ssh-to-age")
		}
		privateKey = *privKeyPtr
		publicKey = *pubKeyPtr
		fmt.Printf("Using SSH key: %s\n", hintStyle.Render(sshKey))
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return errors.Wrap(err, "generate age key")
		}
		privateKey = identity.String()
		publicKey = identity.Recipient().String()
		fmt.Println(hintStyle.Render("No SSH ed25519 key found, generated a new age key."))
	}

	if err := storeKey(privateKey); err != nil {
		return errors.Wrap(err, "keyring store")
	}

	fmt.Println(successStyle.Render("Key stored in OS keyring."))
	fmt.Println()
	fmt.Printf("  key: %s\n", keyStyle.Render(publicKey))
	fmt.Printf("   gh: %s\n", hintStyle.Render("https://github.com/"+username))
	fmt.Println()
	fmt.Printf("To add you to a project: shh users add %s\n", username)
	return nil
}

func cmdEncrypt(src string) error {
	if _, err := os.Stat(src); err != nil {
		return errors.Newf("file not found: %s", src)
	}

	plaintext, err := os.ReadFile(src) // #nosec G304 -- src is a CLI argument; user intentionally points to their own .env file
	if err != nil {
		return errors.Wrap(err, "read file")
	}

	secrets := parsePlaintext(string(plaintext))

	recipients, err := defaultRecipients()
	if err != nil {
		return err
	}

	// If .env.enc already exists, preserve its recipients
	dest := src + ".enc"
	if existing, err := loadEncryptedFile(dest); err == nil {
		recipients = existing.Recipients
	}

	ef, err := encryptSecrets(secrets, recipients)
	if err != nil {
		return err
	}

	if err := saveEncryptedFile(dest, ef); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Encrypted %s -> %s", src, dest)))
	fmt.Printf("You can now delete %s.\n", src)
	return nil
}

func cmdList(file string) error {
	secrets, err := loadSecrets(file)
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(secrets) {
		fmt.Println(k)
	}
	return nil
}

func cmdEnv(file string, stderr io.Writer, checkTTY func() bool, quiet bool) error {
	if !quiet && !checkTTY() {
		fmt.Fprintln(stderr, "warning: writing secrets to stdout (not a terminal)")
	}
	secrets, err := loadSecrets(file)
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(secrets) {
		fmt.Printf("export %s=%s\n", k, shellQuote(secrets[k]))
	}
	return nil
}

func cmdEdit(file string) error {
	var secrets map[string]string
	var recipients map[string]string

	if _, err := os.Stat(file); err == nil {
		ef, err := loadEncryptedFile(file)
		if err != nil {
			return err
		}
		secrets, err = decryptSecrets(ef)
		if err != nil {
			return err
		}
		recipients = ef.Recipients
	} else {
		secrets = make(map[string]string)
		var err error
		recipients, err = defaultRecipients()
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

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return errors.Wrap(err, "chmod temp file")
	}

	// Signal handler to clean up temp file
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		os.Remove(tmpPath) // #nosec G104 -- signal handler cannot propagate errors; best-effort cleanup
		os.Exit(1)
	}()
	defer signal.Stop(sigCh)

	if _, err := tmpFile.WriteString(formatPlaintext(secrets)); err != nil {
		tmpFile.Close() // #nosec G104 -- cleanup in error path; primary error already captured
		return errors.Wrap(err, "write temp file")
	}
	if err := tmpFile.Close(); err != nil {
		return errors.Wrap(err, "close temp file")
	}

	infoBefore, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	editorCmd := exec.Command(editor, tmpPath) // #nosec G702,G204 -- EDITOR is a standard Unix convention for user-chosen editor; tmpPath is program-controlled (os.CreateTemp)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	editorCmd.Env = filterEnv(os.Environ(), "SHH_AGE_KEY")
	if err := editorCmd.Run(); err != nil {
		return errors.Wrap(err, "editor")
	}

	infoAfter, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	if infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		fmt.Println("No changes made.")
		return nil
	}

	edited, err := os.ReadFile(tmpPath) // #nosec G304 -- tmpPath is program-controlled (created by os.CreateTemp above)
	if err != nil {
		return errors.Wrap(err, "read edited file")
	}

	newSecrets := parsePlaintext(string(edited))

	for k := range newSecrets {
		if !envVarKeyPattern.MatchString(k) {
			return errors.Newf("invalid key name %q (must match [A-Za-z_][A-Za-z0-9_]*); re-open with 'shh edit' to fix", k)
		}
		if dangerousEnvVars[k] {
			return errors.Newf("setting %q is not allowed (dangerous environment variable); re-open with 'shh edit' to fix", k)
		}
	}

	ef, err := encryptSecrets(newSecrets, recipients)
	if err != nil {
		return err
	}
	return saveEncryptedFile(file, ef)
}

func cmdSet(file, key, value string) error {
	if !envVarKeyPattern.MatchString(key) {
		return errors.Newf("invalid key name %q (must match [A-Za-z_][A-Za-z0-9_]*)", key)
	}
	if dangerousEnvVars[key] {
		return errors.Newf("setting %q is not allowed (dangerous environment variable)", key)
	}

	var secrets map[string]string
	var recipients map[string]string

	if _, err := os.Stat(file); err == nil {
		ef, err := loadEncryptedFile(file)
		if err != nil {
			return err
		}
		secrets, err = decryptSecrets(ef)
		if err != nil {
			return err
		}
		recipients = ef.Recipients
	} else {
		secrets = make(map[string]string)
		var err error
		recipients, err = defaultRecipients()
		if err != nil {
			return err
		}
	}

	_, existed := secrets[key]
	secrets[key] = value

	ef, err := encryptSecrets(secrets, recipients)
	if err != nil {
		return err
	}
	if err := saveEncryptedFile(file, ef); err != nil {
		return err
	}

	if existed {
		fmt.Println(successStyle.Render(fmt.Sprintf("Updated %s in %s.", key, file)))
	} else {
		fmt.Println(successStyle.Render(fmt.Sprintf("Added %s to %s.", key, file)))
	}
	return nil
}

func cmdRm(file, key string) error {
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return err
	}
	secrets, err := decryptSecrets(ef)
	if err != nil {
		return err
	}

	if _, exists := secrets[key]; !exists {
		return errors.Newf("key %q not found in %s", key, file)
	}

	delete(secrets, key)

	newEf, err := encryptSecrets(secrets, ef.Recipients)
	if err != nil {
		return err
	}
	if err := saveEncryptedFile(file, newEf); err != nil {
		return err
	}
	fmt.Println(successStyle.Render(fmt.Sprintf("Removed %s from %s.", key, file)))
	return nil
}

func cmdShell(file string) error {
	secrets, err := loadSecrets(file)
	if err != nil {
		return err
	}

	env := filterEnv(os.Environ(), "SHH_AGE_KEY")
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Println(successStyle.Render("Secrets loaded.") + " Type 'exit' to end session.")
	return syscall.Exec(shell, []string{shell}, env) // #nosec G702,G204 -- SHELL is a standard Unix convention for user's preferred shell; user owns their environment
}

// --- Run Command ---

func parseRunArgs(args []string) (file string, cmdArgs []string) {
	for i, a := range args {
		if a == "--" {
			if i > 0 {
				file = args[0]
			}
			if i+1 < len(args) {
				cmdArgs = args[i+1:]
			}
			return file, cmdArgs
		}
	}
	// No -- separator: no file, all args are the command
	if len(args) > 0 {
		return "", args
	}
	return "", nil
}

func cmdRun(file string, args []string) error {
	if len(args) == 0 {
		return errors.New("no command specified (usage: shh run -- <command> [args...])")
	}

	secrets, err := loadSecrets(file)
	if err != nil {
		return err
	}

	env := filterEnv(os.Environ(), "SHH_AGE_KEY")
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}

	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 -- user provides the command to run
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return errors.Newf("command exited with status %d", exitErr.ExitCode())
		}
		return errors.Wrap(err, "run command")
	}
	return nil
}

// --- Doctor ---

// DoctorCheck represents the result of a single diagnostic check.
type DoctorCheck struct {
	Name    string
	Status  bool
	Message string
}

func runDoctorChecks(getKeyFn func() (string, error), ghUsernameFn func() string, findSSHKeysFn func() []string, encFile string) []DoctorCheck {
	var checks []DoctorCheck
	var privKey string

	// 1. Age key
	key, err := getKeyFn()
	if err != nil {
		checks = append(checks, DoctorCheck{"age key", false, "no key found (run 'shh init')"})
	} else {
		privKey = key
		pubKey, _ := publicKeyFrom(privKey)
		checks = append(checks, DoctorCheck{"age key", true, pubKey})
	}

	// 2. GitHub CLI
	username := ghUsernameFn()
	if username == "" {
		checks = append(checks, DoctorCheck{"github cli", false, "gh not installed or not logged in"})
	} else {
		checks = append(checks, DoctorCheck{"github cli", true, username})
	}

	// 3. SSH keys
	sshKeys := findSSHKeysFn()
	if len(sshKeys) == 0 {
		checks = append(checks, DoctorCheck{"ssh keys", false, "no ed25519 keys found in ~/.ssh"})
	} else {
		checks = append(checks, DoctorCheck{"ssh keys", true, fmt.Sprintf("%d ed25519 key(s) found", len(sshKeys))})
	}

	// 4. Encrypted file
	ef, err := loadEncryptedFile(encFile)
	if err != nil {
		checks = append(checks, DoctorCheck{"encrypted file", false, fmt.Sprintf("%s not found or invalid", encFile)})
	} else {
		checks = append(checks, DoctorCheck{"encrypted file", true, fmt.Sprintf("%s (%d secret(s), %d recipient(s))", encFile, len(ef.Secrets), len(ef.Recipients))})

		// 5. Recipient check (only if file exists and we have a key)
		if privKey != "" {
			pubKey, _ := publicKeyFrom(privKey)
			found := false
			for _, pk := range ef.Recipients {
				if pk == pubKey {
					found = true
					break
				}
			}
			if found {
				checks = append(checks, DoctorCheck{"recipient", true, "your key is authorized"})
			} else {
				checks = append(checks, DoctorCheck{"recipient", false, "your key is NOT in the recipients list"})
			}
		}
	}

	return checks
}

func cmdDoctor() error {
	checks := runDoctorChecks(getKey, ghUsername, findSSHEd25519Keys, findEncFile())

	hasFailure := false
	for _, c := range checks {
		var icon string
		if c.Status {
			icon = successStyle.Render("✓")
		} else {
			icon = errorStyle.Render("✗")
			hasFailure = true
		}
		fmt.Printf("  %s %-16s %s\n", icon, c.Name, hintStyle.Render(c.Message))
	}

	if hasFailure {
		return errors.New("some checks failed")
	}
	return nil
}

// --- Key Management ---

func usersListCmd() error {
	file := findEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found (run 'shh set' first)", defaultEncryptedFile)
	}

	var myKey string
	if priv, err := getKey(); err == nil {
		myKey, _ = publicKeyFrom(priv)
	}

	fmt.Println(headerStyle.Render("Authorized users"))
	i := 0
	for _, name := range sortedKeys(ef.Recipients) {
		i++
		pubKey := ef.Recipients[name]
		marker := ""
		if pubKey == myKey {
			marker = " " + youStyle.Render("(you)")
		}
		fmt.Printf("  %d. %s  %s%s\n", i, keyStyle.Render(pubKey), nameStyle.Render(name), marker)
	}
	return nil
}

// resolveUserKey resolves the argument to an age public key and a recipient name.
// Age public keys (age1...) are accepted directly.
// Everything else is treated as a GitHub username.
func resolveUserKey(arg string) (ageKey, name string, err error) {
	if ageKeyPattern.MatchString(arg) {
		return arg, arg, nil
	}

	username := arg
	if !githubUserPattern.MatchString(username) {
		return "", "", errors.Newf("invalid GitHub username or age key: %q", username)
	}

	fmt.Printf("Fetching SSH keys for github.com/%s...\n", username)
	resp, err := httpClient.Get("https://github.com/" + username + ".keys")
	if err != nil {
		return "", "", errors.Wrap(err, "fetch keys")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", errors.Newf("could not fetch keys for %q (HTTP %d)", username, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", "", err
	}

	var ed25519Line string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ssh-ed25519") {
			ed25519Line = line
			break
		}
	}
	if ed25519Line == "" {
		return "", "", errors.Newf("no ed25519 SSH key found for %q (age requires ed25519)", username)
	}

	ageKeyPtr, err := sshtoa.SSHPublicKeyToAge([]byte(ed25519Line))
	if err != nil {
		return "", "", errors.Wrap(err, "ssh-to-age")
	}
	fmt.Printf("Converted %s's SSH key -> %s\n", username, keyStyle.Render(*ageKeyPtr))

	return *ageKeyPtr, "https://github.com/" + username, nil
}

func usersAddCmd(args []string) error {
	newKey, name, err := resolveUserKey(args[0])
	if err != nil {
		return err
	}
	file := findEncFile()
	var ef *EncryptedFile

	if _, err := os.Stat(file); err == nil {
		ef, err = loadEncryptedFile(file)
		if err != nil {
			return err
		}
	} else {
		// Create new empty file with current user
		recipients, err := defaultRecipients()
		if err != nil {
			return err
		}
		ef, err = encryptSecrets(map[string]string{}, recipients)
		if err != nil {
			return err
		}
	}

	// Check for duplicate key
	for _, pk := range ef.Recipients {
		if pk == newKey {
			fmt.Println("User already present.")
			return nil
		}
	}

	// Check for name collision
	if _, exists := ef.Recipients[name]; exists {
		return errors.Newf("name %q already in use (specify a different name)", name)
	}

	// Add recipient and re-wrap data key
	newRecipients := make(map[string]string, len(ef.Recipients)+1)
	for k, v := range ef.Recipients {
		newRecipients[k] = v
	}
	newRecipients[name] = newKey

	if err := reWrapDataKey(ef, newRecipients); err != nil {
		return err
	}

	if err := saveEncryptedFile(file, ef); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Added %s.", recipientDisplayName(name))))
	return nil
}

func usersRemoveCmd(args []string) error {
	target := args[0]

	file := findEncFile()
	ef, err := loadEncryptedFile(file)
	if err != nil {
		return errors.Newf("no %s found", defaultEncryptedFile)
	}

	// Resolve number to key
	names := sortedKeys(ef.Recipients)
	if n, err := strconv.Atoi(target); err == nil {
		if n < 1 || n > len(names) {
			return errors.Newf("invalid key number: %d", n)
		}
		target = ef.Recipients[names[n-1]]
	}

	// Find and remove the key
	var removedName string
	newRecipients := make(map[string]string)
	for name, pk := range ef.Recipients {
		if pk == target || name == target || recipientDisplayName(name) == target {
			removedName = name
		} else {
			newRecipients[name] = pk
		}
	}

	if removedName == "" {
		return errors.Newf("key not found: %s", target)
	}
	if len(newRecipients) == 0 {
		return errors.New("cannot remove the last key")
	}

	// Decrypt all secrets, then re-encrypt with a fresh data key.
	// This ensures the removed user's knowledge of the old data key is useless.
	secrets, err := decryptSecrets(ef)
	if err != nil {
		return err
	}

	newEf, err := encryptSecrets(secrets, newRecipients)
	if err != nil {
		return err
	}

	if err := saveEncryptedFile(file, newEf); err != nil {
		return err
	}

	fmt.Println(successStyle.Render(fmt.Sprintf("Removed key: %s (%s)", removedName, target)))
	fmt.Println(hintStyle.Render("Data key rotated — all secrets re-encrypted."))
	return nil
}

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/keyring"
)

func Execute() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, errorStyle.Render("error: "+err.Error()))
		os.Exit(1)
	}
}

func mustBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func envFlag(cmd *cobra.Command) {
	cmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
}

func encFile(cmd *cobra.Command, args []string) (string, error) {
	name, _ := cmd.Flags().GetString("env")
	return envutil.ResolveFileE(name, args)
}

// secretValue reads "-" from stdin so the secret never lands in argv.
func secretValue(value string) (string, error) {
	if value != "-" {
		return value, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", errors.Wrap(err, "read value from stdin")
	}
	return strings.TrimRight(string(data), "\n"), nil
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "shh",
		Short:         "Encrypted .env management with age encryption",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate age key and store in OS keyring",
		RunE:  runInit,
	}
	rootCmd.AddCommand(initCmd)

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Log in (auto-detects SSH key via GitHub, or --identity / --passphrase / --qr-file)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pass, _ := cmd.Flags().GetBool("passphrase"); pass {
				return runLoginPassphrase()
			}
			if qrFile, _ := cmd.Flags().GetString("qr-file"); qrFile != "" {
				return runLoginQRFile(qrFile)
			}
			if id, _ := cmd.Flags().GetString("identity"); id != "" {
				return runLoginIdentity(id)
			}
			return runLogin(cmd, args)
		},
	}
	loginCmd.Flags().String("identity", "", "Enroll a provided age identity: a file path or an AGE-SECRET-KEY-… / AGE-PLUGIN-… string (YubiKey, Secure Enclave)")
	loginCmd.Flags().Bool("passphrase", false, "Derive your key from a passphrase (brain key); prompts, never stored")
	loginCmd.Flags().String("qr-file", "", "Enroll from a QR image (PNG/JPEG) containing AGE-SECRET-KEY-… (paper recovery)")
	rootCmd.AddCommand(loginCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show your public key and recipient name",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdWhoami()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "logout",
		Short: "Remove age key from OS keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdLogout()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "encrypt <file>",
		Short: "Encrypt a .env file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdEncrypt(args[0])
		},
	})

	listCmd := &cobra.Command{
		Use:   "list [file]",
		Short: "List secret keys (names only, no values)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := encFile(cmd, args)
			if err != nil {
				return err
			}
			return cmdList(file)
		},
	}
	envFlag(listCmd)
	rootCmd.AddCommand(listCmd)

	envCmd := &cobra.Command{
		Use:   "env [file]",
		Short: "Print secrets as export statements (requires --stdout)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stdout, _ := cmd.Flags().GetBool("stdout")
			file, err := encFile(cmd, args)
			if err != nil {
				return err
			}
			return cmdEnv(file, stdout, os.Stderr)
		},
	}
	envFlag(envCmd)
	envCmd.Flags().Bool("stdout", false, "Write secrets to stdout (required; secrets are not printed without it)")
	rootCmd.AddCommand(envCmd)

	editCmd := &cobra.Command{
		Use:   "edit [file]",
		Short: "Edit secrets in $EDITOR",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := encFile(cmd, args)
			if err != nil {
				return err
			}
			return cmdEdit(file)
		},
	}
	envFlag(editCmd)
	rootCmd.AddCommand(editCmd)

	setCmd := &cobra.Command{
		Use:   "set <KEY> <VALUE|--> [file]",
		Short: "Add or update a secret (use - as VALUE to read from stdin)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := encFile(cmd, nil)
			if err != nil {
				return err
			}
			if len(args) > 2 {
				file = args[2]
			}
			value, err := secretValue(args[1])
			if err != nil {
				return err
			}
			return cmdSet(file, args[0], value)
		},
	}
	envFlag(setCmd)
	rootCmd.AddCommand(setCmd)

	rmCmd := &cobra.Command{
		Use:     "rm <KEY> [file]",
		Aliases: []string{"unset"},
		Short:   "Remove a secret",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := encFile(cmd, nil)
			if err != nil {
				return err
			}
			if len(args) > 1 {
				file = args[1]
			}
			return cmdRm(file, args[0])
		},
	}
	envFlag(rmCmd)
	rootCmd.AddCommand(rmCmd)

	getCmd := &cobra.Command{
		Use:   "get <KEY> [file]",
		Short: "Print a single secret value",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			quiet, _ := cmd.Flags().GetBool("quiet")
			file, err := encFile(cmd, nil)
			if err != nil {
				return err
			}
			if len(args) > 1 {
				file = args[1]
			}
			return cmdGet(file, args[0], os.Stderr, func() bool {
				return term.IsTerminal(int(os.Stdout.Fd())) // #nosec G115 -- file descriptors always fit in int
			}, quiet)
		},
	}
	envFlag(getCmd)
	getCmd.Flags().BoolP("quiet", "q", false, "Suppress non-TTY warning")
	rootCmd.AddCommand(getCmd)

	shellCmd := &cobra.Command{
		Use:     "shell [file]",
		Aliases: []string{"sh"},
		Short:   "Start a subshell with secrets loaded",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := encFile(cmd, args)
			if err != nil {
				return err
			}
			return cmdShell(file)
		},
	}
	envFlag(shellCmd)
	rootCmd.AddCommand(shellCmd)

	runCmd := &cobra.Command{
		Use:                "run [file] -- <command> [args...]",
		Short:              "Run a command with secrets in the environment",
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, cmdArgs := parseRunArgs(args)
			if len(cmdArgs) == 0 {
				return fmt.Errorf("usage: shh run [file] -- <command> [args...]")
			}
			return cmdRun(file, cmdArgs)
		},
	}
	rootCmd.AddCommand(runCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "Check your shh setup for common issues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdDoctor()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:    "merge <ancestor> <ours> <theirs>",
		Short:  "Git merge driver for .env.enc files",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdMerge(args[0], args[1], args[2])
		},
	})

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

	addCmd := &cobra.Command{
		Use:   "add [github-username | age-public-key]",
		Short: "Add a user by GitHub username, age public key, or generate a deploy key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			key, _ := cmd.Flags().GetString("key")
			if pass, _ := cmd.Flags().GetBool("passphrase"); pass {
				if name == "" {
					return errors.New("--passphrase requires --name (e.g. --name failsafe)")
				}
				k, err := passphraseRecipient()
				if err != nil {
					return err
				}
				key = k
			}
			opts := usersAddOpts{
				QR:    mustBool(cmd, "qr"),
				QROut: mustString(cmd, "qr-out"),
			}
			return usersAddCmd(args, name, key, opts)
		},
	}
	addCmd.Flags().String("name", "", "Name for a non-GitHub recipient (e.g. production-deploy)")
	addCmd.Flags().String("key", "", "Age public key (optional with --name; generated if omitted)")
	addCmd.Flags().Bool("passphrase", false, "Derive the recipient from a passphrase (brain key); prompts for it")
	addCmd.Flags().Bool("qr", false, "When generating a secret key, print a terminal QR (for paper / 1Password scan)")
	addCmd.Flags().String("qr-out", "", "When generating a secret key, write a PNG QR to this path (0600)")
	usersCmd.AddCommand(addCmd)

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

	templateCmd := &cobra.Command{
		Use:   "template <file> [env-file]",
		Short: "Render a template with secrets substituted",
		Long:  "Replace {{SECRET_NAME}} placeholders in a template file with decrypted secret values. Output goes to stdout.",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := envutil.FindEncFile()
			if len(args) > 1 {
				file = args[1]
			}
			return cmdTemplate(args[0], file)
		},
	}
	rootCmd.AddCommand(templateCmd)

	return rootCmd
}

// loadEncryptedFile loads an encrypted file, attempting auto-resolve on parse failure.
func loadEncryptedFile(path string) (*encfile.EncryptedFile, error) {
	ef, err := encfile.Load(path)
	if err != nil {
		// Check if this file is in a git merge conflict
		privKey, keyErr := keyring.GetKey()
		if keyErr == nil {
			if resolved, resolveErr := encfile.TryAutoResolve(path, privKey); resolveErr == nil {
				return resolved, nil
			}
		}
		return nil, err
	}
	return ef, nil
}

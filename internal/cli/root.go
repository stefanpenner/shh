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

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "shh",
		Short:         "Encrypted .env management with age encryption",
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
			file, err := envutil.ResolveFileE(env, args)
			if err != nil {
				return err
			}
			return cmdList(file)
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
			file, err := envutil.ResolveFileE(env, args)
			if err != nil {
				return err
			}
			return cmdEnv(file, os.Stderr, func() bool {
				return term.IsTerminal(int(os.Stdout.Fd())) // #nosec G115 -- file descriptors always fit in int
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
			file, err := envutil.ResolveFileE(env, args)
			if err != nil {
				return err
			}
			return cmdEdit(file)
		},
	}
	editCmd.Flags().StringP("env", "e", "", "Environment name (e.g. production → production.env.enc)")
	rootCmd.AddCommand(editCmd)

	// set command
	setCmd := &cobra.Command{
		Use:   "set <KEY> <VALUE|--> [file]",
		Short: "Add or update a secret (use - as VALUE to read from stdin)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, _ := cmd.Flags().GetString("env")
			file, err := envutil.ResolveFileE(env, nil)
			if err != nil {
				return err
			}
			if len(args) > 2 {
				file = args[2]
			}
			value := args[1]
			if value == "-" {
				// Read value from stdin to avoid secret exposure in process args / ps output.
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return errors.Wrap(err, "read value from stdin")
				}
				value = strings.TrimRight(string(data), "\n")
			}
			return cmdSet(file, args[0], value)
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
			file, err := envutil.ResolveFileE(env, nil)
			if err != nil {
				return err
			}
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
			file, err := envutil.ResolveFileE(env, args)
			if err != nil {
				return err
			}
			return cmdShell(file)
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
				return fmt.Errorf("usage: shh run [file] -- <command> [args...]")
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

	// merge driver command (for git)
	rootCmd.AddCommand(&cobra.Command{
		Use:    "merge <ancestor> <ours> <theirs>",
		Short:  "Git merge driver for .env.enc files",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmdMerge(args[0], args[1], args[2])
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

	addCmd := &cobra.Command{
		Use:   "add [github-username | age-public-key]",
		Short: "Add a user by GitHub username, age public key, or generate a deploy key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			key, _ := cmd.Flags().GetString("key")
			return usersAddCmd(args, name, key)
		},
	}
	addCmd.Flags().String("name", "", "Name for a non-GitHub recipient (e.g. production-deploy)")
	addCmd.Flags().String("key", "", "Age public key (optional with --name; generated if omitted)")
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

	// template command
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

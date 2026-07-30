package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/keyring"
)

// appendSecrets adds secret key=value pairs to env, skipping any keys in
// DangerousEnvVars. This is defense-in-depth: the storage layer already
// rejects dangerous keys, but a file crafted outside of `shh set`/`shh edit`
// (e.g., via direct TOML manipulation by a rogue recipient, or via git merge)
// could still contain them.
func appendSecrets(env []string, secrets map[string]string) []string {
	for k, v := range secrets {
		if envutil.DangerousEnvVars[k] {
			fmt.Fprintf(os.Stderr, "warning: skipping dangerous env var %q from secrets file\n", k)
			continue
		}
		env = append(env, k+"="+v)
	}
	return env
}

func cmdShell(file string) error {
	secrets, err := loadRunSecrets(file)
	if err != nil {
		return err
	}

	env := appendSecrets(envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY", "SHH_PLAINTEXT", "SHH_ALLOWED_AGE_PLUGINS"), secrets)

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Println(successStyle.Render("Secrets loaded.") + " Type 'exit' to end session.")
	return syscall.Exec(shell, []string{shell}, env) // #nosec G702,G204
}

// loadRunSecrets loads secrets for run/shell. SHH_PLAINTEXT is an explicit
// operator escape hatch (CI): skip age identity entirely so throwaway CI
// never needs a decrypt key.
func loadRunSecrets(file string) (map[string]string, error) {
	if os.Getenv("SHH_PLAINTEXT") != "" {
		return encfile.LoadSecrets(file, "")
	}
	privKey, err := keyring.GetKey()
	if err != nil {
		return nil, err
	}
	return encfile.LoadSecrets(file, privKey)
}

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
	if file == "" {
		file = envutil.FindEncFile()
	}

	// No file given (e.g. `shh run -- cmd`): fall back to the default .env.enc,
	// matching list/env/get/shell rather than trying to open an empty path.
	if file == "" {
		file = envutil.FindEncFile()
	}

	secrets, err := loadRunSecrets(file)
	if err != nil {
		return err
	}

	env := appendSecrets(envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY", "SHH_PLAINTEXT", "SHH_ALLOWED_AGE_PLUGINS"), secrets)

	cmd := exec.Command(args[0], args[1:]...) // #nosec G204
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

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

func cmdShell(file string) error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(file, privKey)
	if err != nil {
		return err
	}

	env := envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY", "SHH_PLAINTEXT")
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Println(successStyle.Render("Secrets loaded.") + " Type 'exit' to end session.")
	return syscall.Exec(shell, []string{shell}, env) // #nosec G702,G204
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

	privKey, err := keyring.GetKey()
	if err != nil {
		return err
	}
	secrets, err := encfile.LoadSecrets(file, privKey)
	if err != nil {
		return err
	}

	env := envutil.FilterEnv(os.Environ(), "SHH_AGE_KEY", "SHH_PLAINTEXT")
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}

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

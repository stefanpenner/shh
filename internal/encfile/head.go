package encfile

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
)

// RecipientsDifferFromHEAD reports whether current is not the recipient set in HEAD.
// A path with no HEAD vault, or a directory that is not a git work tree, does not differ.
// A HEAD vault that does not parse is an error.
func RecipientsDifferFromHEAD(path string, current map[string]string) (bool, error) {
	dir, _ := encDir(path)
	if !gitWorkTree(dir) {
		return false, nil
	}
	top, err := gitCmd(dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return false, errors.Wrap(err, "git root")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	root, err := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	if err != nil {
		return false, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false, err
	}
	rel = filepath.ToSlash(rel)

	show := gitCmd(dir, "show", "HEAD:"+rel)
	out, err := show.Output()
	if err != nil {
		if headVaultMissing(gitStderr(err)) {
			return false, nil
		}
		return false, errors.Wrapf(err, "read HEAD vault: %s", strings.TrimSpace(gitStderr(err)))
	}
	ef, err := LoadFromBytes(out)
	if err != nil {
		return false, errors.Wrap(err, "parse HEAD vault")
	}
	return !sameRecipients(current, ef.Recipients), nil
}

func sameRecipients(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func gitWorkTree(dir string) bool {
	out, err := gitCmd(dir, "rev-parse", "--is-inside-work-tree").Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func headVaultMissing(msg string) bool {
	return strings.Contains(msg, "but not in") ||
		strings.Contains(msg, "does not exist in") ||
		strings.Contains(msg, "invalid object name")
}

func gitStderr(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(exitErr.Stderr)
	}
	return ""
}

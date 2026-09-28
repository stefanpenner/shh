package encfile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/merge"
	"github.com/stefanpenner/shh/internal/recipientmerge"
)

// TryAutoResolve checks if a file is in a git merge conflict and resolves it.
// Returns the resolved EncryptedFile or an error if not conflicted / resolution fails.
func TryAutoResolve(path string, privateKey string) (*EncryptedFile, error) {
	dir, base := encDir(path)

	ancestor, ours, theirs, err := gitConflictSides(dir, base)
	if err != nil {
		return nil, err
	}

	merged, err := MergeFile(ancestor, ours, theirs, privateKey,
		"cannot auto-resolve: conflicting keys: %s", "re-encrypt")
	if err != nil {
		return nil, err
	}

	if err := Save(path, merged); err != nil {
		return nil, errors.Wrap(err, "save resolved file")
	}
	if err := gitAdd(dir, base); err != nil {
		return nil, errors.Wrap(err, "git add")
	}

	fmt.Fprintf(os.Stderr, "Auto-resolved merge conflict in %s (%d secrets, %d recipients).\n",
		path, len(merged.Secrets), len(merged.Recipients))
	return merged, nil
}

// MergeFile decrypts three sides, merges secrets and recipients, and re-encrypts.
// conflictFmt is a one-%s error when keys conflict. encryptNote wraps a seal failure.
func MergeFile(ancestor, ours, theirs *EncryptedFile, privateKey, conflictFmt, encryptNote string) (*EncryptedFile, error) {
	secrets, recipients, conflicts, err := decryptAndMerge(ancestor, ours, theirs, privateKey)
	if len(conflicts) > 0 {
		return nil, errors.Newf(conflictFmt, strings.Join(conflicts, ", "))
	}
	if err != nil {
		return nil, err
	}

	ef, err := EncryptSecrets(secrets, recipients)
	if err != nil {
		return nil, errors.Wrap(err, encryptNote)
	}
	return ef, nil
}

func decryptAndMerge(ancestor, ours, theirs *EncryptedFile, privateKey string) (map[string]string, map[string]string, []string, error) {
	if _, _, err := recipientmerge.Decide(sameRecipients(ours.Recipients, theirs.Recipients)); err != nil {
		return nil, nil, nil, err
	}

	ancestorSecrets, err := decryptSide(ancestor, privateKey, "ancestor")
	if err != nil {
		return nil, nil, nil, err
	}
	oursSecrets, err := decryptSide(ours, privateKey, "ours")
	if err != nil {
		return nil, nil, nil, err
	}
	theirsSecrets, err := decryptSide(theirs, privateKey, "theirs")
	if err != nil {
		return nil, nil, nil, err
	}

	mergedSecrets, conflicts, err := merge.MergeSecrets(ancestorSecrets, oursSecrets, theirsSecrets)
	if err != nil {
		return nil, nil, conflicts, err
	}
	return mergedSecrets, ours.Recipients, nil, nil
}

func decryptSide(ef *EncryptedFile, privateKey, label string) (map[string]string, error) {
	secrets, err := DecryptSecrets(ef, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt "+label)
	}
	return secrets, nil
}

func encDir(path string) (dir, base string) {
	dir = filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	return dir, filepath.Base(path)
}

func gitConflictSides(dir, base string) (*EncryptedFile, *EncryptedFile, *EncryptedFile, error) {
	out, err := gitCmd(dir, "ls-files", "-u", "--", base).Output()
	if err != nil || len(out) == 0 {
		return nil, nil, nil, errors.New("not a merge conflict")
	}

	ancestor, err := gitStage(dir, base, "1", "ancestor")
	if err != nil {
		return nil, nil, nil, err
	}
	ours, err := gitStage(dir, base, "2", "ours")
	if err != nil {
		return nil, nil, nil, err
	}
	theirs, err := gitStage(dir, base, "3", "theirs")
	if err != nil {
		return nil, nil, nil, err
	}
	return ancestor, ours, theirs, nil
}

func gitStage(dir, base, stage, label string) (*EncryptedFile, error) {
	out, err := gitCmd(dir, "show", ":"+stage+":"+base).Output()
	if err != nil {
		return nil, errors.Wrap(err, "git show "+label)
	}
	ef, err := LoadFromBytes(out)
	if err != nil {
		return nil, errors.Wrap(err, "parse "+label)
	}
	return ef, nil
}

func gitAdd(dir, base string) error {
	return gitCmd(dir, "add", "--", base).Run()
}

func gitCmd(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...) // #nosec G204 -- args are fixed git subcommands; no shell involved
	cmd.Dir = dir
	return cmd
}

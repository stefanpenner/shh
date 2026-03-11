package encfile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/merge"
)

// TryAutoResolve checks if a file is in a git merge conflict and resolves it.
// Returns the resolved EncryptedFile or an error if not conflicted / resolution fails.
func TryAutoResolve(path string, privateKey string) (*EncryptedFile, error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	base := filepath.Base(path)

	gitCmd := func(args ...string) *exec.Cmd {
		cmd := exec.Command("git", args...) // #nosec G204 -- args are fixed git subcommands; no shell involved
		cmd.Dir = dir
		return cmd
	}

	out, err := gitCmd("ls-files", "-u", "--", base).Output()
	if err != nil || len(out) == 0 {
		return nil, errors.New("not a merge conflict")
	}

	ancestorData, err := gitCmd("show", ":1:"+base).Output()
	if err != nil {
		return nil, errors.Wrap(err, "git show ancestor")
	}
	oursData, err := gitCmd("show", ":2:"+base).Output()
	if err != nil {
		return nil, errors.Wrap(err, "git show ours")
	}
	theirsData, err := gitCmd("show", ":3:"+base).Output()
	if err != nil {
		return nil, errors.Wrap(err, "git show theirs")
	}

	ancestor, err := LoadFromBytes(ancestorData)
	if err != nil {
		return nil, errors.Wrap(err, "parse ancestor")
	}
	ours, err := LoadFromBytes(oursData)
	if err != nil {
		return nil, errors.Wrap(err, "parse ours")
	}
	theirs, err := LoadFromBytes(theirsData)
	if err != nil {
		return nil, errors.Wrap(err, "parse theirs")
	}

	ancestorSecrets, err := DecryptSecrets(ancestor, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt ancestor")
	}
	oursSecrets, err := DecryptSecrets(ours, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt ours")
	}
	theirsSecrets, err := DecryptSecrets(theirs, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt theirs")
	}

	mergedSecrets, conflicts, err := merge.MergeSecrets(ancestorSecrets, oursSecrets, theirsSecrets)
	if err != nil {
		return nil, errors.Newf("cannot auto-resolve: conflicting keys: %s", strings.Join(conflicts, ", "))
	}

	mergedRecipients := merge.MergeStringMaps(ancestor.Recipients, ours.Recipients, theirs.Recipients)

	newEf, err := EncryptSecrets(mergedSecrets, mergedRecipients)
	if err != nil {
		return nil, errors.Wrap(err, "re-encrypt")
	}

	if err := Save(path, newEf); err != nil {
		return nil, errors.Wrap(err, "save resolved file")
	}

	if err := gitCmd("add", "--", base).Run(); err != nil {
		return nil, errors.Wrap(err, "git add")
	}

	fmt.Fprintf(os.Stderr, "Auto-resolved merge conflict in %s (%d secrets, %d recipients).\n",
		path, len(mergedSecrets), len(mergedRecipients))

	return newEf, nil
}

package envutil

import (
	"regexp"
	"sort"

	"github.com/cockroachdb/errors"
)

var (
	AgeKeyPattern     = regexp.MustCompile(`^age1[a-z0-9]{58}$`)
	GithubUserPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	EnvVarKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// envNamePattern allows alphanumeric, hyphen, and underscore; no path separators.
	envNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

	DangerousEnvVars = map[string]bool{
		// Core identity / path variables
		"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
		// Linux dynamic-linker injection
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		// macOS dynamic-linker injection
		"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
		// Shell startup files executed automatically — setting these to an
		// attacker-controlled path causes arbitrary code execution when a new
		// shell is spawned (e.g. via `shh shell` or `shh run -- bash`).
		"BASH_ENV": true, // sourced by bash for every non-interactive invocation
		"ENV":      true, // sourced by sh/dash/ksh for non-interactive invocations
		// IFS controls shell word-splitting; overriding it breaks scripts that
		// rely on default whitespace splitting and can lead to unexpected behaviour.
		"IFS": true,
		// PROMPT_COMMAND is executed as a shell command before each prompt;
		// injecting it allows arbitrary code execution in interactive shells.
		"PROMPT_COMMAND": true,
	}
)

// ValidateEnvName returns an error if envName contains path separators or other
// characters that could cause path traversal when constructing filenames.
func ValidateEnvName(envName string) error {
	if !envNamePattern.MatchString(envName) {
		return errors.Newf("invalid environment name %q: must match [A-Za-z0-9][A-Za-z0-9_-]*", envName)
	}
	return nil
}

func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

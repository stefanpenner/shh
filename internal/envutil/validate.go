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
		"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
		// Shell startup files: bash sources BASH_ENV on non-interactive invocations;
		// sh sources ENV. Storing these as secrets and injecting them into `shh shell`
		// or `shh run` would execute arbitrary code at shell startup.
		"BASH_ENV": true, "ENV": true,
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

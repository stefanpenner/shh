package envutil

import (
	"regexp"
	"sort"
)

var (
	AgeKeyPattern     = regexp.MustCompile(`^age1[a-z0-9]{58}$`)
	GithubUserPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	EnvVarKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	DangerousEnvVars = map[string]bool{
		"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
	}
)

func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

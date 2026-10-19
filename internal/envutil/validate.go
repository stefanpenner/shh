package envutil

import (
	"regexp"
	"sort"
	"strings"

	"github.com/cockroachdb/errors"
)

var (
	AgeKeyPattern     = regexp.MustCompile(`^age1[a-z0-9]{58}$`)
	GithubUserPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)
	EnvVarKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// envNamePattern allows alphanumeric, hyphen, and underscore; no path separators.
	envNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

	DangerousEnvVars = map[string]bool{
		// shh's own security knobs: a secret must never be able to widen the age
		// plugin allowlist or override the decryption key/plaintext source.
		"SHH_ALLOWED_AGE_PLUGINS": true,
		// Core identity / path variables
		"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
		// Linux dynamic-linker injection
		"LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
		// macOS dynamic-linker injection
		"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FRAMEWORK_PATH": true,
		// Shell startup files: bash sources BASH_ENV on non-interactive invocations;
		// sh sources ENV. Storing these as secrets and injecting them into `shh shell`
		// or `shh run` would execute arbitrary code at shell startup.
		"BASH_ENV": true, "ENV": true,
		// IFS controls shell word-splitting; overriding it breaks scripts that
		// rely on default whitespace splitting and can lead to unexpected behaviour.
		"IFS": true,
		// PROMPT_COMMAND is executed as a shell command before each prompt;
		// injecting it allows arbitrary code execution in interactive shells.
		"PROMPT_COMMAND": true,
		// Zsh startup directory: overriding ZDOTDIR redirects zsh to source
		// attacker-controlled startup files, equivalent to BASH_ENV for zsh.
		"ZDOTDIR": true,
		// Runtime-level code injection: these variables instruct language runtimes
		// to load attacker-controlled code before any application logic runs.
		// A rogue recipient who can craft a valid .env.enc (with knowledge of the
		// data key) could use these to achieve code execution via `shh run`.
		"NODE_OPTIONS":         true, // Node.js: --require / --experimental-loader load arbitrary code
		"JAVA_TOOL_OPTIONS":    true, // JVM: -agentlib/-agentpath load native agents
		"_JAVA_OPTIONS":        true, // alternative JVM option variable (same risk)
		"JDK_JAVA_OPTIONS":     true, // Java 9+ launcher option variable (same risk)
		"PYTHONSTARTUP":        true, // Python: executes an arbitrary file on interpreter startup
		"RUBYOPT":              true, // Ruby: -r flag loads an arbitrary file on startup
		"PERL5OPT":             true, // Perl: -M flag loads an arbitrary module on startup
		"DOTNET_STARTUP_HOOKS": true, // .NET: loads an arbitrary assembly before Main()
		// More dynamic-linker / libc loading hooks.
		"LD_AUDIT": true, "LD_ORIGIN_PATH": true,
		"GCONV_PATH": true, "LOCPATH": true, "NLSPATH": true, "HOSTALIASES": true,
		// Tools that execute a user-supplied command line.
		"GIT_SSH_COMMAND": true, "GIT_SSH": true, "GIT_ASKPASS": true, "SSH_ASKPASS": true,
		"GIT_EXTERNAL_DIFF": true, "GIT_PAGER": true, "GIT_PROXY_COMMAND": true,
		"GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_COUNT": true,
		"TAR_OPTIONS": true, "PAGER": true, "MANPAGER": true, "LESSOPEN": true, "LESSCLOSE": true,
		"EDITOR": true, "VISUAL": true,
		// Extra shell behaviour/startup knobs.
		"SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "CDPATH": true, "GLOBIGNORE": true,
		// Language module search paths: load attacker-controlled code.
		"PYTHONPATH": true, "PYTHONHOME": true, "PERL5LIB": true, "RUBYLIB": true, "NODE_PATH": true,
	}

	// dangerousEnvPrefixes block whole families of names, e.g. exported bash
	// functions (BASH_FUNC_name%%) that run code when a child bash starts.
	dangerousEnvPrefixes = []string{"BASH_FUNC_"}
)

// IsDangerousEnvVar reports whether key must never be stored or injected.
func IsDangerousEnvVar(key string) bool {
	if DangerousEnvVars[key] {
		return true
	}
	for _, p := range dangerousEnvPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

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

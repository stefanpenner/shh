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
		"NODE_OPTIONS":        true, // Node.js: --require / --experimental-loader load arbitrary code
		"JAVA_TOOL_OPTIONS":   true, // JVM: -agentlib/-agentpath load native agents
		"_JAVA_OPTIONS":       true, // alternative JVM option variable (same risk)
		"JDK_JAVA_OPTIONS":    true, // Java 9+ launcher option variable (same risk)
		"PYTHONSTARTUP":       true, // Python: executes an arbitrary file on interpreter startup
		"RUBYOPT":             true, // Ruby: -r flag loads an arbitrary file on startup
		"PERL5OPT":            true, // Perl: -M flag loads an arbitrary module on startup
		"DOTNET_STARTUP_HOOKS": true, // .NET: loads an arbitrary assembly before Main()
		// Module/library search-path injection: a rogue recipient who can craft a
		// valid .env.enc could set these to a directory they control, causing the
		// runtime to load attacker-supplied modules when `shh run` executes a
		// program that imports from the standard library (e.g. `python app.py`).
		"PYTHONPATH": true, // Python: prepended to sys.path; enables malicious module shadowing
		"RUBYLIB":    true, // Ruby: prepended to $LOAD_PATH; enables malicious library shadowing
		"PERL5LIB":   true, // Perl: prepended to @INC; enables malicious module shadowing
		"NODE_PATH":  true, // Node.js: additional module directories; enables malicious package shadowing
		"CLASSPATH":  true, // JVM: class/jar search path; enables malicious class injection
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

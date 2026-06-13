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
		// macOS dynamic-linker injection (primary paths and fallback paths)
		"DYLD_INSERT_LIBRARIES":        true,
		"DYLD_LIBRARY_PATH":            true,
		"DYLD_FRAMEWORK_PATH":          true,
		"DYLD_FALLBACK_LIBRARY_PATH":   true, // macOS: fallback search path for shared libraries
		"DYLD_FALLBACK_FRAMEWORK_PATH": true, // macOS: fallback search path for frameworks
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
		// Runtime flag injection: these variables pass flags to language runtimes
		// that cause them to load attacker-controlled code before application logic.
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
		// Runtime path injection: these variables prepend attacker-controlled directories
		// to the module/library search path, causing runtimes to load attacker code
		// when the application imports any module that exists in the attacker's directory.
		// This is the path-based counterpart to the flag-based injection vars above.
		"PYTHONPATH": true, // Python: prepended to sys.path; imports attacker modules
		"NODE_PATH":  true, // Node.js: searched by require() before node_modules
		"RUBYLIB":    true, // Ruby: prepended to $LOAD_PATH; loaded before system libs
		"PERLLIB":    true, // Perl: prepended to @INC; loaded before system libs
		"PERL5LIB":   true, // Perl: same as PERLLIB (Perl 5 variant; takes precedence)
		"CLASSPATH":  true, // Java: class search path; attacker classes loaded before JDK classes
		"GEM_HOME":   true, // Ruby: directory where gems are installed and loaded from
		"GEM_PATH":   true, // Ruby: colon-separated list of gem directories searched on require
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

package envutil

import (
	"os"
	"os/user"
	"path/filepath"
)

const DefaultEncryptedFile = ".env.enc"

// FindEncFile walks up from the current directory looking for .env.enc.
// Returns the path if found, otherwise falls back to DefaultEncryptedFile
// in the current directory (so that create operations still work).
func FindEncFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return DefaultEncryptedFile
	}
	for {
		candidate := filepath.Join(dir, DefaultEncryptedFile)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return DefaultEncryptedFile
}

func FileArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return FindEncFile()
}

func EnvFlag(envName string) string {
	if envName == "" {
		return ""
	}
	return envName + ".env.enc"
}

func ResolveFile(envName string, args []string) string {
	if envName != "" {
		return EnvFlag(envName)
	}
	return FileArg(args)
}

func CurrentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}

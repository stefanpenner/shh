package encfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/envutil"
)

type EncryptedFile struct {
	Version     int               `toml:"version"`
	MAC         string            `toml:"mac"`
	DataKey     string            `toml:"data_key,omitempty"`     // v1 only, kept for migration
	Recipients  map[string]string `toml:"recipients"`
	WrappedKeys map[string]string `toml:"wrapped_keys,omitempty"` // v2: per-recipient wrapped data keys
	Secrets     map[string]string `toml:"secrets"`
}

func Load(path string) (*EncryptedFile, error) {
	var ef EncryptedFile
	if _, err := toml.DecodeFile(path, &ef); err != nil {
		return nil, errors.Wrap(err, "parse encrypted file")
	}
	return normalize(&ef)
}

func LoadFromBytes(data []byte) (*EncryptedFile, error) {
	var ef EncryptedFile
	if _, err := toml.Decode(string(data), &ef); err != nil {
		return nil, errors.Wrap(err, "parse encrypted file")
	}
	return normalize(&ef)
}

func normalize(ef *EncryptedFile) (*EncryptedFile, error) {
	if ef.Version != 1 && ef.Version != 2 {
		return nil, errors.Newf("unsupported file version: %d (expected 1 or 2)", ef.Version)
	}
	if ef.Recipients == nil {
		ef.Recipients = make(map[string]string)
	}
	if ef.WrappedKeys == nil {
		ef.WrappedKeys = make(map[string]string)
	}
	if ef.Secrets == nil {
		ef.Secrets = make(map[string]string)
	}
	return ef, nil
}

func Marshal(ef *EncryptedFile) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "version = %d\n", ef.Version)
	fmt.Fprintf(&buf, "mac = %q\n", ef.MAC)

	buf.WriteString("\n[recipients]\n")
	for _, name := range envutil.SortedKeys(ef.Recipients) {
		if err := validateTOMLValue(ef.Recipients[name]); err != nil {
			return nil, errors.Wrapf(err, "recipient %q", name)
		}
		fmt.Fprintf(&buf, "%s = %q\n", tomlKey(name), ef.Recipients[name])
	}

	buf.WriteString("\n[wrapped_keys]\n")
	for _, name := range envutil.SortedKeys(ef.WrappedKeys) {
		if err := validateTOMLValue(ef.WrappedKeys[name]); err != nil {
			return nil, errors.Wrapf(err, "wrapped key %q", name)
		}
		fmt.Fprintf(&buf, "%s = %q\n", tomlKey(name), ef.WrappedKeys[name])
	}

	buf.WriteString("\n[secrets]\n")
	for _, k := range envutil.SortedKeys(ef.Secrets) {
		if err := validateTOMLValue(ef.Secrets[k]); err != nil {
			return nil, errors.Wrapf(err, "secret %q", k)
		}
		fmt.Fprintf(&buf, "%s = %q\n", tomlKey(k), ef.Secrets[k])
	}

	return buf.Bytes(), nil
}

func Save(path string, ef *EncryptedFile) error {
	data, err := Marshal(ef)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".shh-*.tmp")
	if err != nil {
		return errors.Wrap(err, "create temp file")
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()        // #nosec G104 -- cleanup in error path
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup
		return errors.Wrap(err, "write temp file")
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()        // #nosec G104 -- cleanup in error path
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup
		return errors.Wrap(err, "chmod temp file")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup
		return errors.Wrap(err, "close temp file")
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName) // #nosec G104 -- best-effort cleanup
		return errors.Wrap(err, "rename temp file")
	}
	return nil
}

package crypto

import (
	"bytes"
	"encoding/base64"
	"io"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
)

func WrapDataKeyForRecipient(dataKey []byte, pubKey string) (string, error) {
	rec, err := age.ParseX25519Recipient(pubKey)
	if err != nil {
		return "", errors.Wrapf(err, "parse recipient %s", pubKey)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return "", errors.Wrap(err, "age encrypt")
	}
	if _, err := w.Write(dataKey); err != nil {
		return "", errors.Wrap(err, "write data key")
	}
	if err := w.Close(); err != nil {
		return "", errors.Wrap(err, "close age writer")
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func WrapDataKeyPerRecipient(dataKey []byte, recipients map[string]string) (map[string]string, error) {
	wrapped := make(map[string]string, len(recipients))
	for name, pubKey := range recipients {
		w, err := WrapDataKeyForRecipient(dataKey, pubKey)
		if err != nil {
			return nil, errors.Wrapf(err, "wrap data key for %s", name)
		}
		wrapped[name] = w
	}
	return wrapped, nil
}

func UnwrapDataKey(wrapped string, privateKey string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode data key")
	}
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "parse age identity")
	}
	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return nil, errors.Wrap(err, "age decrypt data key")
	}
	key, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "read unwrapped key")
	}
	if len(key) != 32 {
		return nil, errors.Newf("unwrapped key has unexpected length %d (expected 32)", len(key))
	}
	return key, nil
}

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
)

func PublicKeyFrom(privateKey string) (string, error) {
	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "parse age identity")
	}
	return identity.Recipient().String(), nil
}

const FileVersion = 2

func GenerateDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.Wrap(err, "generate data key")
	}
	return key, nil
}

func EncryptValue(dataKey []byte, keyName string, plaintext string) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", errors.Wrap(err, "create cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "create GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "generate nonce")
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(keyName))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptValue(dataKey []byte, keyName string, encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.Wrap(err, "base64 decode")
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", errors.Wrap(err, "create cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "create GCM")
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], []byte(keyName))
	if err != nil {
		return "", errors.Wrap(err, "decrypt")
	}
	return string(plaintext), nil
}

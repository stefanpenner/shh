package shhcore

import (
	"filippo.io/age"

	"github.com/stefanpenner/shh/internal/encfile"
)

// SampleVault is a throwaway vault. Identity opens File. The values are not real secrets.
type SampleVault struct {
	Identity string
	File     []byte
}

// Sample builds one throwaway vault. It does not read the iCloud key.
func Sample() (*SampleVault, error) {
	owner, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	ef, err := encfile.EncryptSecrets(
		map[string]string{"B_KEY": "beta", "A_KEY": "alpha"},
		map[string]string{
			"https://github.com/example": owner.Recipient().String(),
			"https://github.com/octocat": other.Recipient().String(),
		},
	)
	if err != nil {
		return nil, err
	}
	raw, err := encfile.Marshal(ef)
	if err != nil {
		return nil, err
	}
	return &SampleVault{Identity: owner.String(), File: raw}, nil
}

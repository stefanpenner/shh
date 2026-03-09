package cli

import (
	"fmt"
	"os"

	"filippo.io/age"
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"

	"github.com/stefanpenner/shh/internal/envutil"
	"github.com/stefanpenner/shh/internal/github"
	"github.com/stefanpenner/shh/internal/keyring"
	"github.com/stefanpenner/shh/internal/sshkeys"
)

func requireGHUsername() (string, error) {
	return github.RequireUsername()
}

func runInit(cmd *cobra.Command, args []string) error {
	if key, err := keyring.GetKey(); err == nil {
		pubKey, err := keyring.PublicKeyFrom(key)
		if err != nil {
			return err
		}
		fmt.Println("Already initialized. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	var privateKey, publicKey string

	// Try to find an ed25519 SSH key to derive from
	sshKeyPaths := sshkeys.FindEd25519Keys()
	if len(sshKeyPaths) > 0 {
		sshKey := sshKeyPaths[0]
		sshKeyData, err := os.ReadFile(sshKey) // #nosec G304
		if err != nil {
			return errors.Wrap(err, "read SSH key")
		}
		privKeyPtr, pubKeyPtr, err := sshkeys.ToAge(sshKeyData, sshKey)
		if err != nil {
			return errors.Wrap(err, "ssh-to-age")
		}
		privateKey = *privKeyPtr
		publicKey = *pubKeyPtr
		fmt.Printf("Using SSH key: %s\n", hintStyle.Render(sshKey))
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return errors.Wrap(err, "generate age key")
		}
		privateKey = identity.String()
		publicKey = identity.Recipient().String()
		fmt.Println(hintStyle.Render("No SSH ed25519 key found, generated a new age key."))
	}

	if err := keyring.StoreKey(privateKey); err != nil {
		return errors.Wrap(err, "keyring store")
	}

	fmt.Println(successStyle.Render("Key stored in OS keyring."))
	fmt.Println()
	fmt.Printf("  key: %s\n", keyStyle.Render(publicKey))
	fmt.Printf("   gh: %s\n", hintStyle.Render("https://github.com/"+username))
	fmt.Println()
	fmt.Printf("To add you to a project: shh users add %s\n", username)
	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	if key, err := keyring.GetKey(); err == nil {
		pubKey, _ := keyring.PublicKeyFrom(key)
		fmt.Println("Already logged in. Your public key:")
		fmt.Printf("  %s\n", keyStyle.Render(pubKey))
		return nil
	}

	username, err := requireGHUsername()
	if err != nil {
		return err
	}
	fmt.Printf("GitHub user: %s\n", nameStyle.Render(username))

	// Load recipients from .env.enc if it exists
	var recipients map[string]string
	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		recipients = ef.Recipients
	}

	// Find local SSH keys and try to match against recipients
	for _, sshPath := range sshkeys.FindEd25519Keys() {
		data, _ := os.ReadFile(sshPath)
		privPtr, pubPtr, err := sshkeys.ToAge(data, sshPath)
		if err != nil {
			continue
		}
		if recipients != nil {
			for _, rk := range recipients {
				if rk == *pubPtr {
					if err := keyring.StoreKey(*privPtr); err != nil {
						return errors.Wrap(err, "keyring store")
					}
					fmt.Printf("Matched SSH key %s\n", hintStyle.Render(sshPath))
					fmt.Println(successStyle.Render("Key stored in OS keyring."))
					fmt.Printf("  %s\n", keyStyle.Render(*pubPtr))
					return nil
				}
			}
		}
	}

	if recipients != nil {
		return errors.Newf("your SSH key is not in the recipients list\n  ask a teammate to run: shh users add %s", username)
	}

	return errors.New("no .env.enc found — run 'shh init' to start a new project")
}

func cmdWhoami() error {
	privKey, err := keyring.GetKey()
	if err != nil {
		return errors.New("not logged in (run 'shh init' or 'shh login')")
	}
	pubKey, err := keyring.PublicKeyFrom(privKey)
	if err != nil {
		return err
	}

	fmt.Printf("  key: %s\n", keyStyle.Render(pubKey))

	// Check if we're in a project's recipients list
	if ef, err := loadEncryptedFile(envutil.FindEncFile()); err == nil {
		for name, pk := range ef.Recipients {
			if pk == pubKey {
				fmt.Printf(" user: %s\n", nameStyle.Render(name))
				break
			}
		}
	}

	// Check which SSH key this corresponds to
	for _, sshPath := range sshkeys.FindEd25519Keys() {
		data, err := os.ReadFile(sshPath)
		if err != nil {
			continue
		}
		_, pubPtr, err := sshkeys.ToAge(data, sshPath)
		if err != nil {
			continue
		}
		if *pubPtr == pubKey {
			fmt.Printf("  ssh: %s\n", hintStyle.Render(sshPath))
			break
		}
	}

	return nil
}

func cmdLogout() error {
	err := keyring.DeleteKey()
	if err != nil {
		return errors.New("no key found in keyring")
	}
	fmt.Println(successStyle.Render("Age key removed from OS keyring."))
	return nil
}

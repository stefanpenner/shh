package cli

import (
	"fmt"
	"os"

	"github.com/cockroachdb/errors"

	"github.com/stefanpenner/shh/internal/encfile"
	"github.com/stefanpenner/shh/internal/qr"
)

func cmdPaperEncode(file, out string) error {
	data, err := os.ReadFile(file) // #nosec G304 -- file is a CLI argument
	if err != nil {
		return errors.Wrap(err, "read vault")
	}
	if _, err := encfile.LoadFromBytes(data); err != nil {
		return errors.New("paper QR encodes an encrypted vault, not a plaintext env file")
	}
	n, err := qr.WriteVaultQRs(data, out)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %d QR codes to %s.\n", n, out)
	fmt.Println("Print the sheet. A scan restores the encrypted vault. It does not show secret values.")
	fmt.Println("Remove the PNG files after you print them. Do not commit them.")
	return nil
}

func cmdPaperDecode(src, out string) error {
	if out == "" {
		return errors.New("pass --out for the restored vault")
	}
	if _, err := os.Stat(out); err == nil {
		return errors.Newf("%s already exists", out)
	}
	data, err := qr.ReadVaultQRs(src)
	if err != nil {
		return err
	}
	if _, err := encfile.LoadFromBytes(data); err != nil {
		return errors.New("scanned sheet is not a shh vault")
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return errors.Wrap(err, "write vault")
	}
	fmt.Printf("Restored %s (%d bytes).\n", out, len(data))
	return nil
}

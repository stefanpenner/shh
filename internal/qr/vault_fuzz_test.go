package qr

import "testing"

func FuzzParseFrame(f *testing.F) {
	vault := []byte("version = 2\nmac = \"abcd\"\n")
	frames, err := SplitVault(vault)
	if err != nil {
		f.Fatal(err)
	}
	text, err := FormatFrame(frames[0])
	if err != nil {
		f.Fatal(err)
	}
	f.Add(text)
	f.Add("")
	f.Add("https://evil.example")
	f.Add("SHHENV1 1 1 aaaaaaaa AAAA")
	f.Add(string([]byte{0, 1, 255}))
	f.Fuzz(func(t *testing.T, in string) {
		frame, err := ParseFrame(in)
		if err != nil {
			return
		}
		if frame.Index < 1 || frame.Index > frame.Total || frame.Total > MaxParts {
			t.Fatalf("frame escaped bounds: %+v", frame)
		}
		if len(frame.Data) == 0 || len(frame.Data) > rawChunk {
			t.Fatalf("data escaped bounds: %d", len(frame.Data))
		}
	})
}

func FuzzAssembleSplit(f *testing.F) {
	f.Add([]byte("version = 2\n"))
	f.Add([]byte{0, 1, 2, 255})
	f.Fuzz(func(t *testing.T, vault []byte) {
		if len(vault) == 0 || len(vault) > MaxParts*rawChunk {
			return
		}
		frames, err := SplitVault(vault)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Assemble(frames)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(vault) {
			t.Fatal("round trip changed the vault")
		}
	})
}

package filename

import (
	"testing"

	rcCrypt "github.com/rclone/rclone/backend/crypt"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/obscure"
)

func TestStandardMatchesRclone(t *testing.T) {
	for _, enc := range []string{EncodingBase64, EncodingBase32, EncodingBase32768} {
		t.Run(enc, func(t *testing.T) {
			c := newTestCipher(t, Config{
				Password:                "pass",
				Salt:                    "salt",
				FileNameEncryption:      ModeStandard,
				DirectoryNameEncryption: true,
				FileNameEncoding:        enc,
				EncryptedSuffix:         ".bin",
			})
			rc := newRcloneCipher(t, ModeStandard, enc, true)
			for _, name := range []string{"1/12/123", "hello world.txt", "dir/hello-v2001-02-03-040506-123.txt"} {
				got := c.EncryptFileName(name)
				want := rc.EncryptFileName(name)
				if got != want {
					t.Fatalf("EncryptFileName(%q)=%q want %q", name, got, want)
				}
				dec, err := c.DecryptFileName(want)
				if err != nil {
					t.Fatal(err)
				}
				if dec != name {
					t.Fatalf("DecryptFileName(%q)=%q want %q", want, dec, name)
				}
			}
		})
	}
}

func TestObfuscateMatchesRclone(t *testing.T) {
	c := newTestCipher(t, Config{
		Password:                "pass",
		Salt:                    "salt",
		FileNameEncryption:      ModeObfuscate,
		DirectoryNameEncryption: true,
		FileNameEncoding:        EncodingBase64,
		EncryptedSuffix:         ".bin",
	})
	rc := newRcloneCipher(t, ModeObfuscate, EncodingBase64, true)
	for _, name := range []string{"1/12/123/!hello", "hello-v2001-02-03-040506-123.txt", "Pi-Π.txt"} {
		got := c.EncryptFileName(name)
		want := rc.EncryptFileName(name)
		if got != want {
			t.Fatalf("EncryptFileName(%q)=%q want %q", name, got, want)
		}
		dec, err := c.DecryptFileName(want)
		if err != nil {
			t.Fatal(err)
		}
		if dec != name {
			t.Fatalf("DecryptFileName(%q)=%q want %q", want, dec, name)
		}
	}
}

func TestBase16384AndAutoDetection(t *testing.T) {
	enc := newTestCipher(t, Config{
		Password:                "pass",
		Salt:                    "salt",
		FileNameEncryption:      ModeStandard,
		DirectoryNameEncryption: true,
		FileNameEncoding:        EncodingBase16384,
	})
	encrypted := enc.EncryptFileName("目录/hello.txt")

	dec := newTestCipher(t, Config{
		Password:                "pass",
		Salt:                    "salt",
		FileNameEncryption:      ModeStandard,
		DirectoryNameEncryption: true,
		FileNameEncoding:        EncodingBase64,
	})
	got, err := dec.DecryptFileName(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if got != "目录/hello.txt" {
		t.Fatalf("DecryptFileName=%q", got)
	}
}

func TestStreamModeRecoveryAndCRC(t *testing.T) {
	c := newTestCipher(t, Config{
		Password:                "pass",
		Salt:                    "salt",
		FileNameEncryption:      ModeStream,
		DirectoryNameEncryption: true,
		FileNameEncoding:        EncodingBase16384,
		StripOrigExt:            true,
	})
	encrypted := c.EncryptFileName("目录/hello.txt")
	got, err := c.DecryptFileName(encrypted + ".jpg")
	if err != nil {
		t.Fatal(err)
	}
	if got != "目录/hello.txt" {
		t.Fatalf("DecryptFileName=%q", got)
	}
	if _, err := c.DecryptFileName(encrypted + "x"); err == nil {
		t.Fatal("expected crc or decode error")
	}
}

func newTestCipher(t *testing.T, cfg Config) *Cipher {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newRcloneCipher(t *testing.T, mode, enc string, dirNameEncrypt bool) *rcCrypt.Cipher {
	t.Helper()
	password, err := obscure.Obscure("pass")
	if err != nil {
		t.Fatal(err)
	}
	salt, err := obscure.Obscure("salt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := rcCrypt.NewCipher(configmap.Simple{
		"password":                  password,
		"password2":                 salt,
		"filename_encryption":       mode,
		"directory_name_encryption": boolString(dirNameEncrypt),
		"filename_encoding":         enc,
		"suffix":                    ".bin",
		"pass_bad_blocks":           "",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

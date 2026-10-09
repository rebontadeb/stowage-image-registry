package vault

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTripAndTamper(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := v.Seal([]byte("private key material"))
	if bytes.Contains(sealed, []byte("private key")) {
		t.Fatal("plaintext visible in sealed data")
	}
	got, err := v.Open(sealed)
	if err != nil || string(got) != "private key material" {
		t.Fatalf("%q %v", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := v.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := v.Open([]byte("short")); err == nil {
		t.Fatal("short input accepted")
	}
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	good, _ := v.Seal([]byte("x"))
	if _, err := other.Open(good); err == nil {
		t.Fatal("wrong master key accepted")
	}
	// two seals of the same data differ (fresh nonce)
	a, _ := v.Seal([]byte("same"))
	b, _ := v.Seal([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("nonce reused")
	}
}

func TestLoadCreatesKeyFileOnceWith0600(t *testing.T) {
	dir := t.TempDir()
	v1, err := Load(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	sealed, _ := v1.Seal([]byte("hello"))
	v2, err := Load(dir, "") // restart: same key
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Open(sealed); err != nil || string(got) != "hello" {
		t.Fatalf("key not stable across loads: %q %v", got, err)
	}
}

func TestLoadFromEnv(t *testing.T) {
	k := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err := Load(t.TempDir(), k); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(t.TempDir(), "not base64!!"); err == nil {
		t.Fatal("bad env key accepted")
	}
	if _, err := Load(t.TempDir(), base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("short env key accepted")
	}
}

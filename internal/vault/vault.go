// Package vault encrypts small secrets (signing-key passwords and private keys) at rest with
// AES-256-GCM under a master key. The master key comes from the environment (a base64 value) or,
// failing that, a file created next to the database with mode 0600. Keeping the master key outside
// the SQLite file means a copy of the database alone does not reveal the secrets.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Vault struct{ aead cipher.AEAD }

// New builds a vault from a 32-byte key.
func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("vault: key must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Vault{g}, nil
}

// Load returns a vault using envKey (base64, 32 bytes) when set, else the key file in dir,
// creating it on first use.
func Load(dir, envKey string) (*Vault, error) {
	if envKey != "" {
		k, err := base64.StdEncoding.DecodeString(envKey)
		if err != nil {
			return nil, fmt.Errorf("vault: master key is not valid base64: %w", err)
		}
		return New(k)
	}
	path := filepath.Join(dir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		return New(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, err
	}
	return New(k)
}

// Seal returns nonce||ciphertext.
func (v *Vault) Seal(plain []byte) ([]byte, error) {
	n := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return v.aead.Seal(n, n, plain, nil), nil
}

func (v *Vault) Open(sealed []byte) ([]byte, error) {
	ns := v.aead.NonceSize()
	if len(sealed) < ns+v.aead.Overhead() {
		return nil, errors.New("vault: ciphertext too short")
	}
	out, err := v.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err != nil {
		return nil, errors.New("vault: cannot decrypt (wrong master key or corrupt data)")
	}
	return out, nil
}

// RandomPassword returns a URL-safe random secret for key passphrases.
func RandomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

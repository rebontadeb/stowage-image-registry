// Package sigkey creates cosign-compatible signing key pairs without running cosign: an ECDSA
// P-256 key whose private half is wrapped in cosign's password-encrypted PEM format (scrypt +
// NaCl secretbox), so the cosign CLI can use it with --key env://VAR and COSIGN_PASSWORD.
package sigkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	privType = "ENCRYPTED SIGSTORE PRIVATE KEY"
	pubType  = "PUBLIC KEY"

	scryptN, scryptR, scryptP = 1 << 15, 8, 1
	saltLen, nonceLen, keyLen = 32, 24, 32
)

type envelope struct {
	KDF struct {
		Name   string `json:"name"`
		Params struct {
			N int `json:"N"`
			R int `json:"r"`
			P int `json:"p"`
		} `json:"params"`
		Salt []byte `json:"salt"`
	} `json:"kdf"`
	Cipher struct {
		Name  string `json:"name"`
		Nonce []byte `json:"nonce"`
	} `json:"cipher"`
	Ciphertext []byte `json:"ciphertext"`
}

// Generate returns a new key pair as PEM: the private key encrypted with password, and the public key.
func Generate(password string) (privPEM, pubPEM string, err error) {
	if password == "" {
		return "", "", errors.New("sigkey: empty password")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	enc, err := encrypt(der, password)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: enc})),
		string(pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: pubDER})), nil
}

func encrypt(plain []byte, password string) ([]byte, error) {
	var e envelope
	e.KDF.Name, e.KDF.Params.N, e.KDF.Params.R, e.KDF.Params.P = "scrypt", scryptN, scryptR, scryptP
	e.KDF.Salt = make([]byte, saltLen)
	e.Cipher.Name, e.Cipher.Nonce = "nacl/secretbox", make([]byte, nonceLen)
	if _, err := rand.Read(e.KDF.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(e.Cipher.Nonce); err != nil {
		return nil, err
	}
	k, err := scrypt.Key([]byte(password), e.KDF.Salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return nil, err
	}
	var key [keyLen]byte
	var nonce [nonceLen]byte
	copy(key[:], k)
	copy(nonce[:], e.Cipher.Nonce)
	e.Ciphertext = secretbox.Seal(nil, plain, &nonce, &key)
	return json.Marshal(e)
}

// PublicKey checks that pubPEM is a P-256 public key and returns it normalised.
func PublicKey(pubPEM string) (string, error) {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil || blk.Type != pubType {
		return "", errors.New("not a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return "", fmt.Errorf("bad public key: %w", err)
	}
	switch k.(type) {
	case *ecdsa.PublicKey:
	default:
		return "", errors.New("only ECDSA public keys are supported")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: blk.Bytes})), nil
}

// decrypt is the inverse of encrypt; used by tests to prove the wrapper round-trips.
func decrypt(enc []byte, password string) ([]byte, error) {
	var e envelope
	if err := json.Unmarshal(enc, &e); err != nil {
		return nil, err
	}
	k, err := scrypt.Key([]byte(password), e.KDF.Salt, e.KDF.Params.N, e.KDF.Params.R, e.KDF.Params.P, keyLen)
	if err != nil {
		return nil, err
	}
	var key [keyLen]byte
	var nonce [nonceLen]byte
	copy(key[:], k)
	copy(nonce[:], e.Cipher.Nonce)
	out, ok := secretbox.Open(nil, e.Ciphertext, &nonce, &key)
	if !ok {
		return nil, errors.New("wrong password or corrupt key")
	}
	return out, nil
}

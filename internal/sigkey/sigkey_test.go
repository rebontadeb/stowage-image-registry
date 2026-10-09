package sigkey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	priv, pub, err := Generate("a-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(priv))
	if blk == nil || blk.Type != "ENCRYPTED SIGSTORE PRIVATE KEY" {
		t.Fatalf("private key PEM: %v", blk)
	}
	der, err := decrypt(blk.Bytes, "a-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("not ECDSA: %T", k)
	}
	pb, _ := pem.Decode([]byte(pub))
	pk, err := x509.ParsePKIXPublicKey(pb.Bytes)
	if err != nil || !ek.PublicKey.Equal(pk) {
		t.Fatalf("public key does not match private: %v", err)
	}
	if _, err := decrypt(blk.Bytes, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if strings.Contains(priv, "PRIVATE KEY-----\nMI") {
		t.Fatal("private key looks unencrypted")
	}
}

func TestPublicKeyValidation(t *testing.T) {
	_, pub, _ := Generate("x")
	if got, err := PublicKey(pub); err != nil || got != pub {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{"", "garbage", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"} {
		if _, err := PublicKey(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, _, err := Generate(""); err == nil {
		t.Error("empty passphrase accepted")
	}
}

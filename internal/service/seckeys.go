package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/sigkey"
	"github.com/rdeb/local-image-registry/internal/store"
)

// ---- signing and trusted keys ----

type KeyInfo struct {
	PublicKey   string    `json:"publicKey"`
	Fingerprint string    `json:"fingerprint"`
	Created     time.Time `json:"created"`
}

type SigningInfo struct {
	SigningKey  *KeyInfo         `json:"signingKey"` // null: this registry cannot sign
	TrustedKeys []store.TrustKey `json:"trustedKeys"`
}

func keyFingerprint(pubPEM string) (string, error) {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return "", errors.New("not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(blk.Bytes); err != nil {
		return "", err
	}
	return fingerprint(blk.Bytes), nil
}

func (s *Service) SigningInfo(registry string) (SigningInfo, error) {
	if s.sec == nil {
		return SigningInfo{}, ErrSecurityDisabled
	}
	if _, err := s.st.Get(registry); err != nil {
		return SigningInfo{}, err
	}
	out := SigningInfo{}
	if k, err := s.st.GetSigningKey(registry); err == nil {
		fp, _ := keyFingerprint(k.PublicPEM)
		out.SigningKey = &KeyInfo{PublicKey: k.PublicPEM, Fingerprint: fp, Created: k.Created}
	} else if !errors.Is(err, store.ErrNotFound) {
		return out, err
	}
	keys, err := s.st.TrustKeys(registry)
	out.TrustedKeys = keys
	return out, err
}

// CreateSigningKey generates the registry's signing key. The private key and its random
// passphrase are stored encrypted under the master key; the public half becomes a trusted key.
func (s *Service) CreateSigningKey(registry string) (KeyInfo, error) {
	if s.sec == nil {
		return KeyInfo{}, ErrSecurityDisabled
	}
	if _, err := s.st.Get(registry); err != nil {
		return KeyInfo{}, err
	}
	if _, err := s.st.GetSigningKey(registry); err == nil {
		return KeyInfo{}, fmt.Errorf("%w: a signing key already exists; delete it first to replace it", ErrExists)
	}
	pass, err := vaultPassword()
	if err != nil {
		return KeyInfo{}, err
	}
	priv, pub, err := sigkey.Generate(pass)
	if err != nil {
		return KeyInfo{}, err
	}
	encPriv, err := s.sec.cfg.Vault.Seal([]byte(priv))
	if err != nil {
		return KeyInfo{}, err
	}
	encPass, err := s.sec.cfg.Vault.Seal([]byte(pass))
	if err != nil {
		return KeyInfo{}, err
	}
	if err := s.st.PutSigningKey(store.SigningKey{Registry: registry, PublicPEM: pub, PrivateEnc: encPriv, PasswordEnc: encPass}); err != nil {
		return KeyInfo{}, err
	}
	fp, _ := keyFingerprint(pub)
	if _, err := s.st.AddTrustKey(store.TrustKey{Registry: registry, Label: registry + " signing key", PublicPEM: pub, Fingerprint: fp, Own: true}); err != nil && !errors.Is(err, store.ErrExists) {
		return KeyInfo{}, err
	}
	return KeyInfo{PublicKey: pub, Fingerprint: fp, Created: time.Now().UTC()}, nil
}

// DeleteSigningKey destroys the private key. Its public half stays trusted so images signed
// earlier keep verifying; remove that separately if the key is considered compromised.
func (s *Service) DeleteSigningKey(registry string) error {
	if s.sec == nil {
		return ErrSecurityDisabled
	}
	if _, err := s.st.Get(registry); err != nil {
		return err
	}
	return s.st.DeleteSigningKey(registry)
}

var labelRe = regexp.MustCompile(`^[\p{L}\p{N} ._@()-]{1,64}$`)

func (s *Service) AddTrustKey(registry, label, pubPEM string) (store.TrustKey, error) {
	if s.sec == nil {
		return store.TrustKey{}, ErrSecurityDisabled
	}
	if _, err := s.st.Get(registry); err != nil {
		return store.TrustKey{}, err
	}
	if !labelRe.MatchString(strings.TrimSpace(label)) {
		return store.TrustKey{}, fmt.Errorf("%w: label must be 1-64 letters, digits or . _ @ ( ) -", ErrInvalid)
	}
	norm, err := sigkey.PublicKey(pubPEM)
	if err != nil {
		return store.TrustKey{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	fp, err := keyFingerprint(norm)
	if err != nil {
		return store.TrustKey{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	k, err := s.st.AddTrustKey(store.TrustKey{Registry: registry, Label: strings.TrimSpace(label), PublicPEM: norm, Fingerprint: fp})
	if errors.Is(err, store.ErrExists) {
		return k, fmt.Errorf("%w: that key is already trusted", ErrExists)
	}
	return k, err
}

func (s *Service) RemoveTrustKey(registry string, id int64) error {
	if s.sec == nil {
		return ErrSecurityDisabled
	}
	if _, err := s.st.Get(registry); err != nil {
		return err
	}
	return s.st.DeleteTrustKey(registry, id)
}

// Sign signs the image at repo:ref with the registry's key, then queues a signature check.
func (s *Service) Sign(ctx context.Context, registry, repo, ref, by string) (string, error) {
	if s.sec == nil {
		return "", ErrSecurityDisabled
	}
	if !regclient.ValidRepo(repo) {
		return "", fmt.Errorf("%w: invalid repository name", ErrInvalid)
	}
	sk, err := s.st.GetSigningKey(registry)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNoSigningKey
	}
	if err != nil {
		return "", err
	}
	priv, err := s.sec.cfg.Vault.Open(sk.PrivateEnc)
	if err != nil {
		return "", err
	}
	pass, err := s.sec.cfg.Vault.Open(sk.PasswordEnc)
	if err != nil {
		return "", err
	}
	c, err := s.client(ctx, registry)
	if err != nil {
		return "", err
	}
	digest := ref
	if !digestRe.MatchString(ref) {
		if digest, err = c.Digest(ctx, repo, ref); err != nil {
			return "", mapReg(err)
		}
	}
	a, err := s.toolAccess(ctx, registry)
	if err != nil {
		return "", err
	}
	env := a.cosignEnv()
	env["SIGN_KEY"], env["COSIGN_PASSWORD"] = string(priv), string(pass)
	res, err := s.tool(ctx, s.sec.cfg.Images.Cosign, a,
		[]string{"sign", "--key", "env://SIGN_KEY", "--yes", "--use-signing-config=false", "--tlog-upload=false", a.cosignFlag(), a.ref(repo, digest)},
		env, nil, 3*time.Minute)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", errors.New(redact(toolFailure("cosign sign", res).Error(), a.pass, string(pass)))
	}
	_, _, _ = s.StartScans(ctx, registry, repo, digest, []string{KindSig}, by)
	return digest, nil
}

func vaultPassword() (string, error) { return vaultRandom() }

// ---- SCAP content library ----

const maxContentBytes = 300 << 20

var contentNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var contentFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.xml(\.bz2)?$`)

func (s *Service) ContentList() ([]store.SCAPContent, error) {
	if s.sec == nil {
		return nil, ErrSecurityDisabled
	}
	return s.st.SCAPContentList()
}

func (s *Service) DeleteContent(name string) error {
	if s.sec == nil {
		return ErrSecurityDisabled
	}
	if !contentNameRe.MatchString(name) {
		return store.ErrNotFound
	}
	if err := s.st.DeleteSCAPContent(name); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(s.sec.cfg.DataDir, "scap", name))
}

// AddContentUpload stores OVAL content read from r.
func (s *Service) AddContentUpload(name, filename string, r io.Reader, source, by string) (store.SCAPContent, error) {
	if s.sec == nil {
		return store.SCAPContent{}, ErrSecurityDisabled
	}
	if !contentNameRe.MatchString(name) {
		return store.SCAPContent{}, fmt.Errorf("%w: name must be lowercase letters, digits, dot, dash or underscore, e.g. rhel-9", ErrInvalid)
	}
	if !contentFileRe.MatchString(filename) {
		return store.SCAPContent{}, fmt.Errorf("%w: file must be an OVAL .xml or .xml.bz2 file", ErrInvalid)
	}
	dir := filepath.Join(s.sec.cfg.DataDir, "scap", name)
	tmp := dir + ".tmp-" + randID()
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return store.SCAPContent{}, err
	}
	defer os.RemoveAll(tmp)
	f, err := os.OpenFile(filepath.Join(tmp, filename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return store.SCAPContent{}, err
	}
	h := newSHA()
	head := make([]byte, 0, 8)
	n, err := io.Copy(io.MultiWriter(f, h, &headCapture{buf: &head}), io.LimitReader(r, maxContentBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.SCAPContent{}, err
	}
	if n > maxContentBytes {
		return store.SCAPContent{}, fmt.Errorf("%w: content is larger than %d MB", ErrInvalid, maxContentBytes>>20)
	}
	if n == 0 || !(strings.HasPrefix(string(head), "BZh") || strings.HasPrefix(string(head), "<?xml") || strings.HasPrefix(string(head), "<oval")) {
		return store.SCAPContent{}, fmt.Errorf("%w: this does not look like an XML or bzip2 OVAL file", ErrInvalid)
	}
	if err := os.RemoveAll(dir); err != nil {
		return store.SCAPContent{}, err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return store.SCAPContent{}, err
	}
	c := store.SCAPContent{Name: name, Kind: "oval", Filename: filename, SHA256: hexSum(h), Size: n, Source: source, AddedBy: by}
	if err := s.st.PutSCAPContent(c); err != nil {
		return c, err
	}
	return s.st.GetSCAPContent(name)
}

// AddContentURL downloads OVAL content over HTTPS. The fetch refuses loopback and link-local
// addresses (cloud metadata endpoints in particular) after DNS resolution.
func (s *Service) AddContentURL(ctx context.Context, name, rawURL, by string) (store.SCAPContent, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return store.SCAPContent{}, fmt.Errorf("%w: content URL must be https", ErrInvalid)
	}
	filename := filepath.Base(u.Path)
	if !contentFileRe.MatchString(filename) {
		return store.SCAPContent{}, fmt.Errorf("%w: the URL must end in a file name like rhel-9.oval.xml.bz2", ErrInvalid)
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	client := &http.Client{
		Timeout: 10 * time.Minute,
		Transport: &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: guardedDial(dialer),
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return store.SCAPContent{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return store.SCAPContent{}, fmt.Errorf("%w: download failed: %v", ErrInvalid, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return store.SCAPContent{}, fmt.Errorf("%w: download failed: HTTP %d", ErrInvalid, resp.StatusCode)
	}
	return s.AddContentUpload(name, filename, resp.Body, u.String(), by)
}

// SecurityStatus describes the security tooling for the admin page.
type SecurityStatus struct {
	Enabled bool                `json:"enabled"`
	Images  ToolImages          `json:"images"`
	Workers int                 `json:"workers"`
	Content []store.SCAPContent `json:"content"`
}

func (s *Service) SecurityStatus() (SecurityStatus, error) {
	if s.sec == nil {
		return SecurityStatus{Content: []store.SCAPContent{}}, nil
	}
	c, err := s.st.SCAPContentList()
	return SecurityStatus{Enabled: true, Images: s.sec.cfg.Images, Workers: s.sec.cfg.Workers, Content: c}, err
}

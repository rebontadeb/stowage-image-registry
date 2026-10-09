package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/store"
)

const (
	adminUser = "_admin" // internal htpasswd user; registry usernames may not start with '_'
	realm     = "Registry"

	htpasswdPath = "/auth/htpasswd"
	certPath     = "/certs/tls.crt"
	keyPath      = "/certs/tls.key"
	configPath   = "/etc/distribution/config.yml"
)

var userRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func scheme(r store.Registry) string {
	if r.TLSCert != "" {
		return "https"
	}
	return "http"
}

func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newUser(name, pass string) (store.User, error) {
	if !userRe.MatchString(name) {
		return store.User{}, fmt.Errorf("%w: username must match %s", ErrInvalid, userRe)
	}
	if len(pass) < 8 || len(pass) > 72 {
		return store.User{}, fmt.Errorf("%w: password must be 8-72 bytes", ErrInvalid)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return store.User{}, err
	}
	return store.User{Name: name, Hash: string(h)}, nil
}

// buildSpec renders the full runtime spec for a registry: auth always on, TLS and config optional.
func buildSpec(r store.Registry, users []store.User) (runtime.Spec, error) {
	adminHash, err := bcrypt.GenerateFromPassword([]byte(r.AdminPass), bcrypt.DefaultCost)
	if err != nil {
		return runtime.Spec{}, err
	}
	var ht strings.Builder
	fmt.Fprintf(&ht, "%s:%s\n", adminUser, adminHash)
	for _, u := range users {
		fmt.Fprintf(&ht, "%s:%s\n", u.Name, u.Hash)
	}

	env := map[string]string{}
	for k, v := range r.Env {
		env[k] = v
	}
	env["REGISTRY_AUTH"] = "htpasswd"
	env["REGISTRY_AUTH_HTPASSWD_REALM"] = realm
	env["REGISTRY_AUTH_HTPASSWD_PATH"] = htpasswdPath

	// Files sit in 0700 per-instance dirs on the host; 0644 lets the image's non-root user read them.
	files := []runtime.File{{Path: htpasswdPath, Content: []byte(ht.String()), Mode: 0o644}}
	if r.TLSCert != "" {
		files = append(files,
			runtime.File{Path: certPath, Content: []byte(r.TLSCert), Mode: 0o644},
			runtime.File{Path: keyPath, Content: []byte(r.TLSKey), Mode: 0o644})
		env["REGISTRY_HTTP_TLS_CERTIFICATE"] = certPath
		env["REGISTRY_HTTP_TLS_KEY"] = keyPath
	}
	if r.ConfigYAML != "" {
		files = append(files, runtime.File{Path: configPath, Content: []byte(r.ConfigYAML), Mode: 0o644})
	}
	return runtime.Spec{
		Name: r.Name, Image: r.Image, HostPort: r.HostPort, StorageSize: r.StorageSize,
		Env: env, Files: files,
	}, nil
}

// apply recreates the workload from the stored state, keeping data. The workload is started
// afterwards only when running is true; callers capture that before the first recreate so a
// failed attempt cannot lose it.
func (s *Service) apply(ctx context.Context, r store.Registry, users []store.User, running bool) error {
	st, err := s.drv.Status(ctx, r.Name)
	if err != nil {
		return err
	}
	if st.State != runtime.StateMissing {
		if err := s.drv.Delete(ctx, r.Name, false); err != nil {
			return err
		}
	}
	spec, err := buildSpec(r, users)
	if err != nil {
		return err
	}
	if err := s.drv.Create(ctx, spec); err != nil {
		return err
	}
	if running {
		if err := s.drv.Start(ctx, r.Name); err != nil {
			return err
		}
		s.waitReady(ctx, r)
	}
	return nil
}

// mutate applies fn to the registry's mutable state, persists it and recreates the workload.
// If recreation fails the previous state is restored (best effort) and the error returned.
func (s *Service) mutate(ctx context.Context, name string, fn func(*store.Registry, *[]store.User) error) (View, error) {
	mu := lockFor(name)
	mu.Lock()
	defer mu.Unlock()

	rec, err := s.st.Get(name)
	if err != nil {
		return View{}, err
	}
	users, err := s.st.Users(name)
	if err != nil {
		return View{}, err
	}
	oldRec, oldUsers := rec, append([]store.User(nil), users...)
	st, err := s.drv.Status(ctx, name)
	if err != nil {
		return View{}, err
	}
	running := st.State.Active()

	if err := fn(&rec, &users); err != nil {
		return View{}, err
	}
	if err := s.st.Save(rec, users); err != nil {
		return View{}, err
	}
	if err := s.apply(ctx, rec, users, running); err != nil {
		_ = s.st.Save(oldRec, oldUsers)
		_ = s.apply(context.WithoutCancel(ctx), oldRec, oldUsers, running)
		return View{}, err
	}
	return s.view(ctx, rec), nil
}

// ---- users ----

func (s *Service) Users(ctx context.Context, name string) ([]string, error) {
	if _, err := s.st.Get(name); err != nil {
		return nil, err
	}
	us, err := s.st.Users(name)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(us))
	for _, u := range us {
		names = append(names, u.Name)
	}
	return names, nil
}

// SetUser adds a user or changes their password.
func (s *Service) SetUser(ctx context.Context, name, user, pass string) error {
	nu, err := newUser(user, pass)
	if err != nil {
		return err
	}
	_, err = s.mutate(ctx, name, func(_ *store.Registry, users *[]store.User) error {
		for i := range *users {
			if (*users)[i].Name == user {
				(*users)[i] = nu
				return nil
			}
		}
		*users = append(*users, nu)
		return nil
	})
	return err
}

func (s *Service) RemoveUser(ctx context.Context, name, user string) error {
	_, err := s.mutate(ctx, name, func(_ *store.Registry, users *[]store.User) error {
		for i := range *users {
			if (*users)[i].Name == user {
				*users = append((*users)[:i], (*users)[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
	return err
}

// ---- TLS ----

type TLSInfo struct {
	Enabled  bool      `json:"enabled"`
	NotAfter time.Time `json:"notAfter,omitempty"`
	DNSNames []string  `json:"dnsNames,omitempty"`
	Subject  string    `json:"subject,omitempty"`
	SelfSign bool      `json:"selfSigned,omitempty"`
}

type TLSInput struct {
	Cert     string   `json:"cert"`
	Key      string   `json:"key"`
	Generate bool     `json:"generate"`
	Hosts    []string `json:"hosts"` // extra SANs for a generated cert
}

func (s *Service) TLS(ctx context.Context, name string) (TLSInfo, error) {
	rec, err := s.st.Get(name)
	if err != nil {
		return TLSInfo{}, err
	}
	return tlsInfo(rec.TLSCert), nil
}

func tlsInfo(certPEM string) TLSInfo {
	if certPEM == "" {
		return TLSInfo{}
	}
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		return TLSInfo{Enabled: true}
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return TLSInfo{Enabled: true}
	}
	return TLSInfo{Enabled: true, NotAfter: c.NotAfter, DNSNames: c.DNSNames,
		Subject: c.Subject.String(), SelfSign: c.Subject.String() == c.Issuer.String()}
}

func (s *Service) SetTLS(ctx context.Context, name string, in TLSInput) (TLSInfo, error) {
	cert, key := in.Cert, in.Key
	if in.Generate {
		var err error
		if cert, key, err = selfSigned(name, in.Hosts); err != nil {
			return TLSInfo{}, err
		}
	} else if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
		return TLSInfo{}, fmt.Errorf("%w: cert/key pair: %v", ErrInvalid, err)
	}
	_, err := s.mutate(ctx, name, func(r *store.Registry, _ *[]store.User) error {
		r.TLSCert, r.TLSKey = cert, key
		return nil
	})
	return tlsInfo(cert), err
}

func (s *Service) RemoveTLS(ctx context.Context, name string) error {
	_, err := s.mutate(ctx, name, func(r *store.Registry, _ *[]store.User) error {
		r.TLSCert, r.TLSKey = "", ""
		return nil
	})
	return err
}

func selfSigned(name string, hosts []string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return "", "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		switch {
		case h == "":
		case net.ParseIP(h) != nil:
			tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(h))
		case utf8.ValidString(h) && !strings.ContainsAny(h, " /\\"):
			tpl.DNSNames = append(tpl.DNSNames, h)
		default:
			return "", "", fmt.Errorf("%w: bad host %q", ErrInvalid, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})), nil
}

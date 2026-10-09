// Package service holds runtime-agnostic registry lifecycle logic.
package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/store"
)

var (
	ErrInvalid  = errors.New("invalid input")
	ErrNoPorts  = errors.New("no free port in range")
	ErrNotFound = store.ErrNotFound
	ErrExists   = store.ErrExists

	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
)

type Service struct {
	st      *store.Store
	drv     runtime.Driver
	portMin int
	portMax int
	mu      sync.Mutex // serialises create/delete (port allocation)

	usage usageCache
	tr    *transfers // add-image jobs
	sec   *security  // nil until EnableSecurity

	// readyTimeout bounds how long to wait for a started registry to answer; 0 skips the wait.
	readyTimeout time.Duration
}

func New(st *store.Store, drv runtime.Driver, portMin, portMax int) *Service {
	return &Service{st: st, drv: drv, portMin: portMin, portMax: portMax, readyTimeout: 20 * time.Second, tr: newTransfers()}
}

// SetReadyTimeout sets how long to wait for a started registry to answer; 0 disables the wait
// (for runtimes with no real endpoint, such as the fake one).
func (s *Service) SetReadyTimeout(d time.Duration) { s.readyTimeout = d }

type CreateInput struct {
	Name        string `json:"name"`
	Customer    string `json:"customer"`
	Image       string `json:"image"`
	StorageSize string `json:"storageSize"`
	// Optional first registry user; both or neither.
	Username string `json:"username"`
	Password string `json:"password"`
}

// View is a stored record joined with live runtime state.
type View struct {
	store.Registry
	State        runtime.State `json:"state"`
	Endpoint     string        `json:"endpoint"` // address the backend uses
	Host         string        `json:"host"`     // address clients use (host[:port])
	URL          string        `json:"url"`
	TLS          bool          `json:"tls"`
	CustomConfig bool          `json:"customConfig"`
}

func (s *Service) Create(ctx context.Context, in CreateInput) (View, error) {
	if !nameRe.MatchString(in.Name) {
		return View{}, fmt.Errorf("%w: name must be a DNS label (a-z, 0-9, '-', max 32)", ErrInvalid)
	}
	if strings.TrimSpace(in.Customer) == "" {
		return View{}, fmt.Errorf("%w: tenant required", ErrInvalid)
	}
	if in.Image == "" {
		in.Image = runtime.DefaultImage
	}
	if in.StorageSize == "" {
		in.StorageSize = "10Gi"
	}
	var users []store.User
	if in.Username != "" || in.Password != "" {
		u, err := newUser(in.Username, in.Password)
		if err != nil {
			return View{}, err
		}
		users = append(users, u)
	}
	admin, err := randomSecret()
	if err != nil {
		return View{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	port, err := s.allocPort()
	if err != nil {
		return View{}, err
	}
	rec := store.Registry{
		Name: in.Name, Customer: in.Customer, Image: in.Image,
		HostPort: port, StorageSize: in.StorageSize, CreatedAt: time.Now().UTC(),
		AdminPass: admin,
	}
	if err := s.st.Create(rec, users); err != nil {
		return View{}, err
	}
	fail := func(err error) (View, error) {
		_ = s.drv.Delete(ctx, rec.Name, true)
		_ = s.st.Delete(rec.Name)
		return View{}, err
	}
	spec, err := buildSpec(rec, users)
	if err != nil {
		return fail(err)
	}
	if err := s.drv.Create(ctx, spec); err != nil {
		return fail(err)
	}
	if err := s.drv.Start(ctx, rec.Name); err != nil {
		return fail(err)
	}
	s.waitReady(ctx, rec)
	return s.view(ctx, rec), nil
}

func (s *Service) allocPort() (int, error) {
	used, err := s.st.UsedPorts()
	if err != nil {
		return 0, err
	}
	for p := s.portMin; p <= s.portMax; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, ErrNoPorts
}

func (s *Service) view(ctx context.Context, r store.Registry) View {
	v := View{Registry: r, State: runtime.StateMissing, TLS: r.TLSCert != "", CustomConfig: r.ConfigYAML != ""}
	if st, err := s.drv.Status(ctx, r.Name); err == nil {
		v.State, v.Endpoint = st.State, st.Endpoint
		v.Host = st.PublicHost
		if v.Host == "" {
			v.Host = st.Endpoint
		}
		if v.Host != "" {
			v.URL = scheme(r) + "://" + v.Host
		}
	}
	return v
}

func (s *Service) Get(ctx context.Context, name string) (View, error) {
	r, err := s.st.Get(name)
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, r), nil
}

func (s *Service) List(ctx context.Context) ([]View, error) {
	rs, err := s.st.List()
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rs))
	for _, r := range rs {
		out = append(out, s.view(ctx, r))
	}
	return out, nil
}

func (s *Service) Start(ctx context.Context, name string) (View, error) {
	r, err := s.st.Get(name)
	if err != nil {
		return View{}, err
	}
	if err := s.drv.Start(ctx, name); err != nil {
		return View{}, err
	}
	s.waitReady(ctx, r)
	return s.view(ctx, r), nil
}

func (s *Service) Stop(ctx context.Context, name string) (View, error) {
	r, err := s.st.Get(name)
	if err != nil {
		return View{}, err
	}
	if err := s.drv.Stop(ctx, name); err != nil {
		return View{}, err
	}
	return s.view(ctx, r), nil
}

func (s *Service) Delete(ctx context.Context, name string, removeData bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	mu := lockFor(name)
	mu.Lock()
	defer mu.Unlock()
	if _, err := s.st.Get(name); err != nil {
		return err
	}
	if err := s.drv.Delete(ctx, name, removeData); err != nil {
		return err
	}
	s.usage.drop(name)
	return s.st.Delete(name)
}

// waitReady blocks until a just-started registry answers /v2/ or readyTimeout passes. Best effort:
// callers proceed either way, but later requests no longer race the process start-up.
func (s *Service) waitReady(ctx context.Context, r store.Registry) {
	if s.readyTimeout <= 0 {
		return
	}
	st, err := s.drv.Status(ctx, r.Name)
	if err != nil || st.Endpoint == "" {
		return
	}
	c := regclient.NewManaged(scheme(r)+"://"+st.Endpoint, adminUser, r.AdminPass)
	deadline := time.Now().Add(s.readyTimeout)
	for time.Now().Before(deadline) {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := c.Ping(pctx)
		cancel()
		if err == nil || ctx.Err() != nil {
			return
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return
		}
	}
}

package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rdeb/local-image-registry/internal/store"
)

// DefaultConfig mirrors the image's stock behaviour: filesystem storage, port 5000,
// manifest deletion on, graceful drain.
const DefaultConfig = `version: 0.1
log:
  fields:
    service: registry
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: :5000
  draintimeout: 60s
`

const maxConfigBytes = 64 << 10

var (
	envKeyRe = regexp.MustCompile(`^REGISTRY_[A-Z0-9_]+$`)
	// Env prefixes owned by this service or that would move data off the managed volume/port.
	reservedEnv = []string{"REGISTRY_AUTH", "REGISTRY_HTTP_TLS", "REGISTRY_HTTP_ADDR", "REGISTRY_STORAGE"}
)

type ConfigView struct {
	Config string            `json:"config"` // effective config.yml (default when not customised)
	Custom bool              `json:"custom"`
	Env    map[string]string `json:"env"`
}

type ConfigInput struct {
	Config string            `json:"config"` // empty = reset to image default
	Env    map[string]string `json:"env"`
}

func (s *Service) Config(ctx context.Context, name string) (ConfigView, error) {
	rec, err := s.st.Get(name)
	if err != nil {
		return ConfigView{}, err
	}
	return configView(rec), nil
}

func configView(rec store.Registry) ConfigView {
	v := ConfigView{Config: rec.ConfigYAML, Custom: rec.ConfigYAML != "", Env: rec.Env}
	if !v.Custom {
		v.Config = DefaultConfig
	}
	if v.Env == nil {
		v.Env = map[string]string{}
	}
	return v
}

func (s *Service) SetConfig(ctx context.Context, name string, in ConfigInput) (ConfigView, error) {
	cfg := in.Config
	if strings.TrimSpace(cfg) == strings.TrimSpace(DefaultConfig) {
		cfg = ""
	}
	if cfg != "" {
		if err := validateConfig(cfg); err != nil {
			return ConfigView{}, err
		}
	}
	if err := validateEnv(in.Env); err != nil {
		return ConfigView{}, err
	}
	env := map[string]string{}
	for k, v := range in.Env {
		env[k] = v
	}
	v, err := s.mutate(ctx, name, func(r *store.Registry, _ *[]store.User) error {
		r.ConfigYAML, r.Env = cfg, env
		return nil
	})
	if err != nil {
		return ConfigView{}, err
	}
	return configView(v.Registry), nil
}

func validateEnv(env map[string]string) error {
	for k, v := range env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("%w: env key %q must match %s", ErrInvalid, k, envKeyRe)
		}
		for _, p := range reservedEnv {
			if strings.HasPrefix(k, p) {
				return fmt.Errorf("%w: %s is managed by the service", ErrInvalid, k)
			}
		}
		if len(v) > 1024 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("%w: bad value for %s", ErrInvalid, k)
		}
	}
	return nil
}

// validateConfig enforces the invariants the service relies on.
func validateConfig(cfg string) error {
	if len(cfg) > maxConfigBytes {
		return fmt.Errorf("%w: config larger than %d bytes", ErrInvalid, maxConfigBytes)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(cfg), &doc); err != nil {
		return fmt.Errorf("%w: yaml: %v", ErrInvalid, err)
	}
	if doc == nil {
		return fmt.Errorf("%w: empty config", ErrInvalid)
	}
	if _, ok := doc["version"]; !ok {
		return fmt.Errorf("%w: missing version", ErrInvalid)
	}
	if _, ok := doc["auth"]; ok {
		return fmt.Errorf("%w: auth is managed by the service (use the users API)", ErrInvalid)
	}
	if v := dig(doc, "http", "tls"); v != nil {
		return fmt.Errorf("%w: http.tls is managed by the service (use the tls API)", ErrInvalid)
	}
	if root, _ := dig(doc, "storage", "filesystem", "rootdirectory").(string); root != "/var/lib/registry" {
		return fmt.Errorf("%w: storage.filesystem.rootdirectory must be /var/lib/registry (the managed volume)", ErrInvalid)
	}
	if en, _ := dig(doc, "storage", "delete", "enabled").(bool); !en {
		return fmt.Errorf("%w: storage.delete.enabled must be true (needed for tag deletion and GC)", ErrInvalid)
	}
	if addr, _ := dig(doc, "http", "addr").(string); !strings.HasSuffix(addr, ":5000") {
		return fmt.Errorf("%w: http.addr must listen on port 5000", ErrInvalid)
	}
	return nil
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

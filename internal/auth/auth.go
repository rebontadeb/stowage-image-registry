// Package auth implements manager sign-in: roles, per-registry scope, sessions, local passwords
// and the account rules around them. OIDC lives in oidc.go and feeds LoginExternal.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rdeb/local-image-registry/internal/store"
)

type Role string

const (
	Admin    Role = "admin"    // everything, including accounts and audit log
	Operator Role = "operator" // manage the registries in scope
	Viewer   Role = "viewer"   // read-only on the registries in scope
)

func ParseRole(s string) (Role, bool) {
	r := Role(s)
	return r, r == Admin || r == Operator || r == Viewer
}

// Perm is the minimum role needed for an action.
type Perm int

const (
	PermNone    Perm = iota // any signed-in user
	PermView                // viewer and up
	PermOperate             // operator and up
	PermAdmin               // admin only
)

func (r Role) Allows(p Perm) bool {
	switch p {
	case PermNone:
		return r != ""
	case PermView:
		return r == Viewer || r == Operator || r == Admin
	case PermOperate:
		return r == Operator || r == Admin
	case PermAdmin:
		return r == Admin
	}
	return false
}

// Principal is the authenticated caller, rebuilt from the database on every request so role and
// scope changes apply immediately.
type Principal struct {
	ID          int64           `json:"id"`
	Username    string          `json:"username"`
	DisplayName string          `json:"displayName"`
	Role        Role            `json:"role"`
	Source      string          `json:"source"`
	All         bool            `json:"allRegistries"`
	Registries  map[string]bool `json:"-"`
	MustChange  bool            `json:"mustChangePassword"`
}

func (p Principal) CanSee(registry string) bool {
	return p.Role == Admin || p.All || p.Registries[registry]
}

func principal(a store.Account) Principal {
	p := Principal{
		ID: a.ID, Username: a.Username, DisplayName: a.DisplayName, Role: Role(a.Role), Source: a.Source,
		All: a.AllRegistries, MustChange: a.MustChange, Registries: map[string]bool{},
	}
	for _, r := range a.Registries {
		p.Registries[r] = true
	}
	return p
}

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUnauthenticated    = errors.New("not signed in")
	ErrDisabled           = errors.New("account is disabled")
	ErrLastAdmin          = errors.New("at least one enabled admin must remain")
	ErrSelf               = errors.New("you cannot do that to your own account")
	ErrInvalid            = errors.New("invalid input")
	ErrNotFound           = store.ErrNotFound
	ErrExists             = store.ErrExists
)

// LockedError is returned while an account or address is throttled.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("too many failed attempts; try again in %d minutes", int(e.RetryAfter.Minutes())+1)
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

type Service struct {
	st          *store.Store
	SessionTTL  time.Duration // idle timeout, extended on use
	MaxLifetime time.Duration // absolute cap
	now         func() time.Time
	th          *throttle
	mu          sync.Mutex // serialises changes that must keep the "last admin" invariant
	dummyHash   []byte
}

func NewService(st *store.Store) *Service {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return &Service{
		st: st, SessionTTL: 8 * time.Hour, MaxLifetime: 24 * time.Hour,
		now: time.Now, th: newThrottle(), dummyHash: dummy,
	}
}

// ---- passwords ----

func ValidatePassword(username, pw string) error {
	switch {
	case len(pw) < 12:
		return fmt.Errorf("%w: password must be at least 12 characters", ErrInvalid)
	case len(pw) > 72:
		return fmt.Errorf("%w: password must be at most 72 bytes", ErrInvalid)
	case username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(username)):
		return fmt.Errorf("%w: password must not contain the username", ErrInvalid)
	case strings.Count(pw, pw[:1]) == len(pw):
		return fmt.Errorf("%w: password is too repetitive", ErrInvalid)
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func randomToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ---- sign-in ----

func (s *Service) newSession(a store.Account) (string, Principal, error) {
	token, hash, err := randomToken()
	if err != nil {
		return "", Principal{}, err
	}
	if err := s.st.CreateSession(hash, a.ID, s.now().Add(s.SessionTTL)); err != nil {
		return "", Principal{}, err
	}
	_ = s.st.TouchLogin(a.ID)
	_ = s.st.PurgeSessions()
	return token, principal(a), nil
}

// Login checks a local password. All failure reasons look identical to the caller.
func (s *Service) Login(username, password, ip string) (string, Principal, error) {
	if wait := s.th.check(username, ip, s.now()); wait > 0 {
		return "", Principal{}, &LockedError{wait}
	}
	a, err := s.st.AccountByUsername(username)
	valid := err == nil && a.Source == "local" && a.PasswordHash != "" && !a.Disabled
	hash := []byte(a.PasswordHash)
	if !valid {
		hash = s.dummyHash // equalise timing with the real path
	}
	cmp := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if !valid || cmp != nil {
		s.th.fail(username, ip, s.now())
		return "", Principal{}, ErrInvalidCredentials
	}
	s.th.ok(username, ip)
	return s.newSession(a)
}

// ExternalIdentity is what an OIDC login hands over after the IdP verified the user.
type ExternalIdentity struct {
	Subject     string
	Username    string
	DisplayName string
	Role        Role
}

// LoginExternal signs in (and on first use provisions) a federated account. Role is taken from
// the IdP on every login; registry scope stays as assigned by an admin.
func (s *Service) LoginExternal(id ExternalIdentity) (string, Principal, error) {
	if id.Subject == "" || !usernameRe.MatchString(id.Username) {
		return "", Principal{}, fmt.Errorf("%w: identity provider returned no usable username", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.st.AccountByOIDCSubject(id.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		a, err = s.st.CreateAccount(store.Account{
			Username: id.Username, DisplayName: id.DisplayName, Role: string(id.Role), Source: "oidc", OIDCSubject: id.Subject,
		})
		if errors.Is(err, store.ErrExists) {
			return "", Principal{}, fmt.Errorf("%w: username %q is already used by another account", ErrExists, id.Username)
		}
		if err != nil {
			return "", Principal{}, err
		}
	case err != nil:
		return "", Principal{}, err
	default:
		if a.Disabled {
			return "", Principal{}, ErrDisabled
		}
		if a.Role != string(id.Role) || a.DisplayName != id.DisplayName {
			if a.Role == string(Admin) && id.Role != Admin {
				if n, _ := s.st.CountActiveAdmins(a.ID); n == 0 {
					return "", Principal{}, ErrLastAdmin
				}
			}
			a.Role, a.DisplayName = string(id.Role), id.DisplayName
			if err := s.st.UpdateAccount(a); err != nil {
				return "", Principal{}, err
			}
		}
	}
	return s.newSession(a)
}

// Authenticate resolves a session token to the current principal, extending the idle timeout.
func (s *Service) Authenticate(token string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrUnauthenticated
	}
	hash := hashToken(token)
	se, err := s.st.GetSession(hash)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	now := s.now()
	if now.After(se.ExpiresAt) || now.After(se.CreatedAt.Add(s.MaxLifetime)) {
		_ = s.st.DeleteSession(hash)
		return Principal{}, ErrUnauthenticated
	}
	a, err := s.st.AccountByID(se.AccountID)
	if err != nil || a.Disabled {
		_ = s.st.DeleteSession(hash)
		return Principal{}, ErrUnauthenticated
	}
	if now.Sub(se.LastSeen) > time.Minute { // bound write rate
		exp := now.Add(s.SessionTTL)
		if limit := se.CreatedAt.Add(s.MaxLifetime); exp.After(limit) {
			exp = limit
		}
		_ = s.st.TouchSession(hash, exp)
	}
	return principal(a), nil
}

func (s *Service) Logout(token string) { _ = s.st.DeleteSession(hashToken(token)) }

// ---- self service ----

func (s *Service) ChangePassword(p Principal, token, current, next string) error {
	a, err := s.st.AccountByID(p.ID)
	if err != nil {
		return err
	}
	if a.Source != "local" {
		return fmt.Errorf("%w: password is managed by your identity provider", ErrInvalid)
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(current)) != nil {
		return ErrInvalidCredentials
	}
	if subtle.ConstantTimeCompare([]byte(current), []byte(next)) == 1 {
		return fmt.Errorf("%w: new password must differ from the current one", ErrInvalid)
	}
	if err := ValidatePassword(a.Username, next); err != nil {
		return err
	}
	h, err := hashPassword(next)
	if err != nil {
		return err
	}
	if err := s.st.SetPassword(a.ID, h, false); err != nil {
		return err
	}
	return s.st.DeleteSessionsFor(a.ID, hashToken(token)) // sign out every other device
}

// ---- administration ----

type NewAccount struct {
	Username, DisplayName, Password string
	Role                            Role
	AllRegistries                   bool
	Registries                      []string
	MustChange                      bool
}

func (s *Service) Accounts() ([]store.Account, error) { return s.st.ListAccounts() }

func (s *Service) Account(id int64) (store.Account, error) { return s.st.AccountByID(id) }

func (s *Service) CreateLocal(n NewAccount) (store.Account, error) {
	if !usernameRe.MatchString(n.Username) {
		return store.Account{}, fmt.Errorf("%w: username must match %s", ErrInvalid, usernameRe)
	}
	if _, ok := ParseRole(string(n.Role)); !ok {
		return store.Account{}, fmt.Errorf("%w: unknown role %q", ErrInvalid, n.Role)
	}
	if err := ValidatePassword(n.Username, n.Password); err != nil {
		return store.Account{}, err
	}
	h, err := hashPassword(n.Password)
	if err != nil {
		return store.Account{}, err
	}
	return s.st.CreateAccount(store.Account{
		Username: n.Username, DisplayName: n.DisplayName, Role: string(n.Role), Source: "local", PasswordHash: h,
		AllRegistries: n.AllRegistries && n.Role != Admin, Registries: n.Registries, MustChange: n.MustChange,
	})
}

// Patch holds optional changes; nil means "leave as is".
type Patch struct {
	DisplayName   *string
	Role          *Role
	Disabled      *bool
	AllRegistries *bool
	Registries    *[]string
}

func (s *Service) Update(actor Principal, id int64, p Patch) (store.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.st.AccountByID(id)
	if err != nil {
		return a, err
	}
	wasActiveAdmin := a.Role == string(Admin) && !a.Disabled
	if p.DisplayName != nil {
		a.DisplayName = *p.DisplayName
	}
	if p.Role != nil {
		if _, ok := ParseRole(string(*p.Role)); !ok {
			return a, fmt.Errorf("%w: unknown role %q", ErrInvalid, *p.Role)
		}
		a.Role = string(*p.Role)
	}
	if p.Disabled != nil {
		if *p.Disabled && id == actor.ID {
			return a, ErrSelf
		}
		a.Disabled = *p.Disabled
	}
	if p.AllRegistries != nil {
		a.AllRegistries = *p.AllRegistries
	}
	if p.Registries != nil {
		a.Registries = *p.Registries
	}
	if a.Role == string(Admin) {
		a.AllRegistries, a.Registries = false, nil // admins see everything; no stale scope to resurrect
	}
	if wasActiveAdmin && (a.Role != string(Admin) || a.Disabled) {
		if n, _ := s.st.CountActiveAdmins(id); n == 0 {
			return a, ErrLastAdmin
		}
	}
	if err := s.st.UpdateAccount(a); err != nil {
		return a, err
	}
	if a.Disabled {
		_ = s.st.DeleteSessionsFor(id, "")
	}
	return s.st.AccountByID(id)
}

// ResetPassword sets a new local password and signs the account out everywhere.
func (s *Service) ResetPassword(id int64, pw string, mustChange bool) error {
	a, err := s.st.AccountByID(id)
	if err != nil {
		return err
	}
	if a.Source != "local" {
		return fmt.Errorf("%w: account is managed by an identity provider", ErrInvalid)
	}
	if err := ValidatePassword(a.Username, pw); err != nil {
		return err
	}
	h, err := hashPassword(pw)
	if err != nil {
		return err
	}
	if err := s.st.SetPassword(id, h, mustChange); err != nil {
		return err
	}
	return s.st.DeleteSessionsFor(id, "")
}

func (s *Service) Delete(actor Principal, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == actor.ID {
		return ErrSelf
	}
	a, err := s.st.AccountByID(id)
	if err != nil {
		return err
	}
	if a.Role == string(Admin) && !a.Disabled {
		if n, _ := s.st.CountActiveAdmins(id); n == 0 {
			return ErrLastAdmin
		}
	}
	return s.st.DeleteAccount(id)
}

// Bootstrap creates the first admin when no account exists. With an empty password it generates
// one and returns it (the account must change it on first sign-in). created is false when
// accounts already exist.
func (s *Service) Bootstrap(username, password string) (generated string, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, err := s.st.CountAccounts(); err != nil || n > 0 {
		return "", false, err
	}
	must := false
	if password == "" {
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			return "", false, err
		}
		password, generated, must = base64.RawURLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), true
	}
	if err := ValidatePassword(username, password); err != nil {
		return "", false, err
	}
	h, err := hashPassword(password)
	if err != nil {
		return "", false, err
	}
	_, err = s.st.CreateAccount(store.Account{Username: username, DisplayName: username, Role: string(Admin), Source: "local", PasswordHash: h, MustChange: must})
	return generated, err == nil, err
}

// ---- throttle ----

const (
	maxUserFails = 5
	maxIPFails   = 30
	failWindow   = 15 * time.Minute
	lockFor      = 5 * time.Minute
)

type tEntry struct {
	n     int
	first time.Time
	until time.Time
}

type throttle struct {
	mu sync.Mutex
	m  map[string]*tEntry
}

func newThrottle() *throttle { return &throttle{m: map[string]*tEntry{}} }

func keys(user, ip string) (string, string) { return "u:" + strings.ToLower(user), "i:" + ip }

func (t *throttle) check(user, ip string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var wait time.Duration
	uk, ik := keys(user, ip)
	for _, k := range []string{uk, ik} {
		if e := t.m[k]; e != nil && now.Before(e.until) && e.until.Sub(now) > wait {
			wait = e.until.Sub(now)
		}
	}
	return wait
}

func (t *throttle) fail(user, ip string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) > 10000 { // bound memory under a spray attack
		for k, e := range t.m {
			if now.After(e.until) && now.Sub(e.first) > failWindow {
				delete(t.m, k)
			}
		}
	}
	uk, ik := keys(user, ip)
	for k, limit := range map[string]int{uk: maxUserFails, ik: maxIPFails} {
		e := t.m[k]
		if e == nil || now.Sub(e.first) > failWindow {
			e = &tEntry{first: now}
			t.m[k] = e
		}
		e.n++
		if e.n >= limit {
			e.until = now.Add(lockFor)
			e.n, e.first = 0, now
		}
	}
}

func (t *throttle) ok(user, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	uk, _ := keys(user, ip)
	delete(t.m, uk) // a good login clears the account counter, not the address counter
}

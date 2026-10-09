package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rdeb/local-image-registry/internal/store"
)

const pw = "correct-horse-battery"

func newSvc(t *testing.T) (*Service, *store.Store, *time.Time) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := NewService(st)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	return s, st, &clock
}

func mustCreate(t *testing.T, s *Service, name string, role Role) store.Account {
	t.Helper()
	a, err := s.CreateLocal(NewAccount{Username: name, Password: pw, Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoginAndSession(t *testing.T) {
	s, _, _ := newSvc(t)
	mustCreate(t, s, "alice", Operator)

	if _, _, err := s.Login("alice", "wrong-password-1", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("bad pw: %v", err)
	}
	if _, _, err := s.Login("nobody", pw, "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user must look the same: %v", err)
	}
	tok, p, err := s.Login("ALICE", pw, "1.1.1.1") // usernames are case-insensitive
	if err != nil || p.Role != Operator {
		t.Fatalf("login: %+v %v", p, err)
	}
	got, err := s.Authenticate(tok)
	if err != nil || got.Username != "alice" {
		t.Fatalf("auth: %+v %v", got, err)
	}
	s.Logout(tok)
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("after logout: %v", err)
	}
	if _, err := s.Authenticate("garbage"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("garbage token accepted")
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	s, _, clock := newSvc(t)
	mustCreate(t, s, "alice", Viewer)
	tok, _, _ := s.Login("alice", pw, "ip")

	*clock = clock.Add(7 * time.Hour) // within idle window: allowed and extended
	if _, err := s.Authenticate(tok); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(7 * time.Hour) // 14h total but only 7h idle: still fine
	if _, err := s.Authenticate(tok); err != nil {
		t.Fatalf("sliding window: %v", err)
	}
	*clock = clock.Add(11 * time.Hour) // 25h since login: past the absolute cap
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("absolute lifetime not enforced: %v", err)
	}

	tok, _, _ = s.Login("alice", pw, "ip")
	*clock = clock.Add(9 * time.Hour) // idle longer than SessionTTL
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("idle timeout not enforced: %v", err)
	}
}

func TestThrottleLocksAfterRepeatedFailures(t *testing.T) {
	s, _, clock := newSvc(t)
	mustCreate(t, s, "alice", Viewer)
	for i := 0; i < maxUserFails; i++ {
		s.Login("alice", "wrong-password-1", "9.9.9.9")
	}
	_, _, err := s.Login("alice", pw, "9.9.9.9") // correct password, but locked
	var le *LockedError
	if !errors.As(err, &le) || le.RetryAfter <= 0 {
		t.Fatalf("want LockedError, got %v", err)
	}
	// attacker locks the username but a different address is also blocked for that user
	if _, _, err := s.Login("alice", pw, "8.8.8.8"); !errors.As(err, &le) {
		t.Fatalf("lock is per username: %v", err)
	}
	*clock = clock.Add(lockFor + time.Second)
	if _, _, err := s.Login("alice", pw, "9.9.9.9"); err != nil {
		t.Fatalf("lock should expire: %v", err)
	}
}

func TestDisabledAccountCannotSignIn(t *testing.T) {
	s, _, _ := newSvc(t)
	admin := mustCreate(t, s, "root", Admin)
	a := mustCreate(t, s, "alice", Operator)
	tok, _, _ := s.Login("alice", pw, "ip")

	off := true
	if _, err := s.Update(Principal{ID: admin.ID}, a.ID, Patch{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("existing session must die when the account is disabled")
	}
	if _, _, err := s.Login("alice", pw, "ip"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
}

func TestLastAdminAndSelfProtection(t *testing.T) {
	s, _, _ := newSvc(t)
	root := mustCreate(t, s, "root", Admin)
	self := Principal{ID: root.ID, Role: Admin}

	viewer := Viewer
	if _, err := s.Update(self, root.ID, Patch{Role: &viewer}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := s.Delete(self, root.ID); !errors.Is(err, ErrSelf) {
		t.Fatalf("self delete: %v", err)
	}
	off := true
	if _, err := s.Update(self, root.ID, Patch{Disabled: &off}); !errors.Is(err, ErrSelf) {
		t.Fatalf("self disable: %v", err)
	}

	other := mustCreate(t, s, "root2", Admin)
	if _, err := s.Update(self, root.ID, Patch{Role: &viewer}); err != nil {
		t.Fatalf("demote with another admin present: %v", err)
	}
	if err := s.Delete(Principal{ID: root.ID}, other.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
}

func TestScopeAndRoles(t *testing.T) {
	s, _, _ := newSvc(t)
	admin := mustCreate(t, s, "root", Admin)
	a, err := s.CreateLocal(NewAccount{Username: "op", Password: pw, Role: Operator, Registries: []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	tok, p, _ := s.Login("op", pw, "ip")
	_ = tok
	if !p.CanSee("acme") || p.CanSee("globex") {
		t.Fatalf("scope: %+v", p)
	}
	all := true
	s.Update(Principal{ID: admin.ID}, a.ID, Patch{AllRegistries: &all})
	got, _ := s.Authenticate(tok)
	if !got.CanSee("globex") {
		t.Fatal("all-registries flag should apply to the live session")
	}
	adm := Admin
	s.Update(Principal{ID: admin.ID}, a.ID, Patch{Role: &adm})
	got, _ = s.Authenticate(tok)
	if got.All || len(got.Registries) != 0 || !got.CanSee("anything") {
		t.Fatalf("admin carries no stale scope: %+v", got)
	}

	for role, want := range map[Role][4]bool{ // none, view, operate, admin
		Viewer:   {true, true, false, false},
		Operator: {true, true, true, false},
		Admin:    {true, true, true, true},
		"":       {false, false, false, false},
	} {
		for i, perm := range []Perm{PermNone, PermView, PermOperate, PermAdmin} {
			if role.Allows(perm) != want[i] {
				t.Errorf("%q perm %d: want %v", role, perm, want[i])
			}
		}
	}
}

func TestPasswordPolicyAndChange(t *testing.T) {
	s, _, _ := newSvc(t)
	for _, bad := range []string{"short", strings.Repeat("a", 20), "xxalicexxxxxxxx", strings.Repeat("x", 73)} {
		if _, err := s.CreateLocal(NewAccount{Username: "alice", Password: bad, Role: Viewer}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	mustCreate(t, s, "alice", Viewer)
	tok1, p, _ := s.Login("alice", pw, "ip")
	tok2, _, _ := s.Login("alice", pw, "ip")

	if err := s.ChangePassword(p, tok1, "wrong-current-pw", "a-new-password-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := s.ChangePassword(p, tok1, pw, pw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same password: %v", err)
	}
	if err := s.ChangePassword(p, tok1, pw, "a-new-password-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok1); err != nil {
		t.Fatal("current session must survive a password change")
	}
	if _, err := s.Authenticate(tok2); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("other sessions must be revoked")
	}
	if _, _, err := s.Login("alice", pw, "ip"); err == nil {
		t.Fatal("old password still works")
	}
}

func TestBootstrap(t *testing.T) {
	s, _, _ := newSvc(t)
	gen, created, err := s.Bootstrap("admin", "")
	if err != nil || !created || len(gen) < 20 {
		t.Fatalf("%q %v %v", gen, created, err)
	}
	_, p, err := s.Login("admin", gen, "ip")
	if err != nil || !p.MustChange || p.Role != Admin {
		t.Fatalf("generated admin must be forced to change password: %+v %v", p, err)
	}
	if _, created, _ := s.Bootstrap("admin2", pw); created {
		t.Fatal("bootstrap must be a no-op once accounts exist")
	}
}

func TestExternalLogin(t *testing.T) {
	s, st, _ := newSvc(t)
	admin := mustCreate(t, s, "root", Admin)

	tok, p, err := s.LoginExternal(ExternalIdentity{Subject: "sub-1", Username: "carol", DisplayName: "Carol", Role: Operator})
	if err != nil || p.Source != "oidc" || p.Role != Operator {
		t.Fatalf("%+v %v", p, err)
	}
	if _, _, err := s.Login("carol", "anything-at-all-1", "ip"); err == nil {
		t.Fatal("federated account must not accept local passwords")
	}
	// role follows the IdP on the next login
	_, p, _ = s.LoginExternal(ExternalIdentity{Subject: "sub-1", Username: "carol", Role: Viewer})
	if p.Role != Viewer {
		t.Fatalf("role not synced: %+v", p)
	}
	if _, err := s.Authenticate(tok); err != nil {
		t.Fatal(err)
	}
	// a different subject must not take over an existing username
	if _, _, err := s.LoginExternal(ExternalIdentity{Subject: "sub-2", Username: "root", Role: Admin}); !errors.Is(err, ErrExists) {
		t.Fatalf("username takeover: %v", err)
	}
	// IdP cannot demote the last admin out of existence
	s.st.CreateAccount(store.Account{Username: "oidcadmin", Role: "admin", Source: "oidc", OIDCSubject: "sub-9"})
	s.Delete(Principal{ID: 999}, admin.ID)
	if _, _, err := s.LoginExternal(ExternalIdentity{Subject: "sub-9", Username: "oidcadmin", Role: Viewer}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demoted by IdP: %v", err)
	}
	_ = st
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	s, _, _ := newSvc(t)
	a := mustCreate(t, s, "alice", Viewer)
	tok, _, _ := s.Login("alice", pw, "ip")
	if err := s.ResetPassword(a.ID, "brand-new-password-9", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("reset must sign the user out")
	}
	_, p, err := s.Login("alice", "brand-new-password-9", "ip")
	if err != nil || !p.MustChange {
		t.Fatalf("%+v %v", p, err)
	}
}

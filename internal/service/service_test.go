package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/store"
)

type fakeDriver struct {
	state   map[string]runtime.State
	failOn  string
	deleted map[string]bool
	specs   map[string]runtime.Spec
	failNth int // fail the Nth Create call (1-based); 0 = never
	creates int
	gcOut   string
	gcErr   error
}

func newFake() *fakeDriver {
	return &fakeDriver{state: map[string]runtime.State{}, deleted: map[string]bool{}, specs: map[string]runtime.Spec{}}
}

func (f *fakeDriver) Create(_ context.Context, s runtime.Spec) error {
	f.creates++
	if f.failOn == "create" || f.creates == f.failNth {
		return errors.New("boom")
	}
	f.specs[s.Name] = s
	f.state[s.Name] = runtime.StateStopped
	return nil
}
func (f *fakeDriver) Start(_ context.Context, n string) error {
	f.state[n] = runtime.StateRunning
	return nil
}
func (f *fakeDriver) Stop(_ context.Context, n string) error {
	f.state[n] = runtime.StateStopped
	return nil
}
func (f *fakeDriver) Delete(_ context.Context, n string, _ bool) error {
	delete(f.state, n)
	f.deleted[n] = true
	return nil
}
func (f *fakeDriver) Status(_ context.Context, n string) (runtime.Status, error) {
	s, ok := f.state[n]
	if !ok {
		return runtime.Status{State: runtime.StateMissing}, nil
	}
	return runtime.Status{State: s, Endpoint: "127.0.0.1:1"}, nil
}
func (f *fakeDriver) RunTool(context.Context, runtime.ToolSpec) (runtime.ToolResult, error) {
	return runtime.ToolResult{}, runtime.ErrUnsupported
}
func (f *fakeDriver) RunGC(context.Context, string) (string, error)    { return f.gcOut, f.gcErr }
func (f *fakeDriver) UsedBytes(context.Context, string) (int64, error) { return 0, nil }

func newSvc(t *testing.T, drv runtime.Driver, pmin, pmax int) *Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, drv, pmin, pmax)
	svc.readyTimeout = 0
	return svc
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newSvc(t, newFake(), 5100, 5101)

	a, err := s.Create(ctx, CreateInput{Name: "acme", Customer: "Acme"})
	if err != nil || a.State != runtime.StateRunning || a.HostPort != 5100 {
		t.Fatalf("create: %+v %v", a, err)
	}
	b, err := s.Create(ctx, CreateInput{Name: "globex", Customer: "Globex"})
	if err != nil || b.HostPort != 5101 {
		t.Fatalf("second create: %+v %v", b, err)
	}
	if _, err := s.Create(ctx, CreateInput{Name: "third", Customer: "x"}); !errors.Is(err, ErrNoPorts) {
		t.Fatalf("want ErrNoPorts, got %v", err)
	}
	if _, err := s.Create(ctx, CreateInput{Name: "acme", Customer: "x"}); !errors.Is(err, ErrNoPorts) && !errors.Is(err, ErrExists) {
		t.Fatalf("dup name: %v", err)
	}

	if v, _ := s.Stop(ctx, "acme"); v.State != runtime.StateStopped {
		t.Fatalf("stop: %+v", v)
	}
	if v, _ := s.Start(ctx, "acme"); v.State != runtime.StateRunning {
		t.Fatalf("start: %+v", v)
	}
	if err := s.Delete(ctx, "acme", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// freed port is reused
	c, err := s.Create(ctx, CreateInput{Name: "initech", Customer: "Initech"})
	if err != nil || c.HostPort != 5100 {
		t.Fatalf("port reuse: %+v %v", c, err)
	}
}

func TestValidation(t *testing.T) {
	s := newSvc(t, newFake(), 5100, 5199)
	for _, in := range []CreateInput{
		{Name: "Bad_Name", Customer: "x"},
		{Name: "", Customer: "x"},
		{Name: "ok", Customer: " "},
	} {
		if _, err := s.Create(context.Background(), in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: want ErrInvalid, got %v", in, err)
		}
	}
}

func TestCreateRollbackOnDriverFailure(t *testing.T) {
	f := newFake()
	f.failOn = "create"
	s := newSvc(t, f, 5100, 5199)
	if _, err := s.Create(context.Background(), CreateInput{Name: "acme", Customer: "x"}); err == nil {
		t.Fatal("want error")
	}
	if l, _ := s.List(context.Background()); len(l) != 0 {
		t.Fatalf("record not rolled back: %+v", l)
	}
}

func TestGCRestartsAndHandlesEmpty(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	s := newSvc(t, f, 5100, 5199)
	if _, err := s.Create(ctx, CreateInput{Name: "acme", Customer: "x"}); err != nil {
		t.Fatal(err)
	}

	// empty registry: driver error is swallowed, registry comes back up
	f.gcOut, f.gcErr = "filesystem: Path not found: /docker/registry/v2/repositories", errors.New("exit 1")
	res, err := s.GC(ctx, "acme")
	if err != nil || res.Output == "" {
		t.Fatalf("empty gc: %+v %v", res, err)
	}
	if f.state["reg"] == runtime.StateStopped || f.state["acme"] != runtime.StateRunning {
		t.Fatalf("not restarted: %v", f.state)
	}

	// real failure: error surfaces, registry still restarted
	f.gcOut, f.gcErr = "disk on fire", errors.New("exit 1")
	if _, err := s.GC(ctx, "acme"); err == nil {
		t.Fatal("want error")
	}
	if f.state["acme"] != runtime.StateRunning {
		t.Fatalf("not restarted after failure: %v", f.state)
	}
}

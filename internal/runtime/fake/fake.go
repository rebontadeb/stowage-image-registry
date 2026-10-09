// Package fake is an in-memory runtime.Driver for API tests and UI development (-runtime fake).
// It never starts anything: registries "run" instantly and have no real endpoint.
package fake

import (
	"context"
	"fmt"
	"sync"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

type Driver struct {
	mu    sync.Mutex
	state map[string]runtime.State
	port  map[string]int

	// Tool, when set, answers RunTool (tests script tool output here).
	Tool func(runtime.ToolSpec) (runtime.ToolResult, error)
	// Tools records every RunTool call.
	Tools []runtime.ToolSpec
	// Endpoints overrides the address reported for a registry (point it at a test server).
	Endpoints map[string]string
}

func New() *Driver {
	return &Driver{state: map[string]runtime.State{}, port: map[string]int{}}
}

func (d *Driver) Create(_ context.Context, s runtime.Spec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state[s.Name] = runtime.StateStopped
	d.port[s.Name] = s.HostPort
	return nil
}

func (d *Driver) set(name string, st runtime.State) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.state[name]; !ok {
		return runtime.ErrNotFound
	}
	d.state[name] = st
	return nil
}

func (d *Driver) Start(_ context.Context, n string) error { return d.set(n, runtime.StateRunning) }
func (d *Driver) Stop(_ context.Context, n string) error  { return d.set(n, runtime.StateStopped) }

func (d *Driver) Delete(_ context.Context, n string, _ bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.state, n)
	return nil
}

func (d *Driver) Status(_ context.Context, n string) (runtime.Status, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.state[n]
	if !ok {
		return runtime.Status{State: runtime.StateMissing}, nil
	}
	ep := fmt.Sprintf("127.0.0.1:%d", d.port[n])
	if o := d.Endpoints[n]; o != "" {
		ep = o
	}
	return runtime.Status{State: st, Endpoint: ep, PublicHost: ep}, nil
}

func (d *Driver) RunGC(context.Context, string) (string, error) {
	return "nothing to collect (fake)", nil
}
func (d *Driver) UsedBytes(context.Context, string) (int64, error) { return 1 << 20, nil }

func (d *Driver) RunTool(_ context.Context, spec runtime.ToolSpec) (runtime.ToolResult, error) {
	d.mu.Lock()
	d.Tools = append(d.Tools, spec)
	fn := d.Tool
	d.mu.Unlock()
	if fn == nil {
		return runtime.ToolResult{}, runtime.ErrUnsupported
	}
	return fn(spec)
}

var _ runtime.Driver = (*Driver)(nil)

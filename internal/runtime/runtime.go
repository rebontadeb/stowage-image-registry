// Package runtime defines the container-runtime-neutral interface the service
// layer uses to manage registry instances. Drivers: podman (now), kubernetes (later).
package runtime

import (
	"context"
	"errors"
	"time"
)

const DefaultImage = "registry.access.redhat.com/hi/distribution:latest"

var (
	ErrNotFound = errors.New("registry instance not found")
	// ErrImage means a container image could not be found or downloaded; the message says which and why.
	ErrImage = errors.New("container image unavailable")
	// ErrUnsupported means the runtime cannot provide this information (e.g. volume usage on a
	// cluster that denies access to kubelet stats).
	ErrUnsupported = errors.New("not supported by this runtime")
)

// File is a file made available inside the registry container (config, htpasswd, certs).
type File struct {
	Path    string // absolute path inside the container
	Content []byte
	Mode    uint32
}

// Spec describes one registry instance, independent of runtime.
type Spec struct {
	Name        string // unique instance name
	Image       string
	HostPort    int // port exposed to clients (podman: host port; k8s: ignored)
	Env         map[string]string
	Files       []File
	StorageSize string // e.g. "10Gi"; honoured by k8s PVC, informational on podman
}

type State string

const (
	StateRunning  State = "running"
	StateStarting State = "starting" // desired running, not yet ready (e.g. pulling the image)
	StateStopped  State = "stopped"
	StateMissing  State = "missing"
)

// Active reports whether the instance is, or is about to be, serving.
func (s State) Active() bool { return s == StateRunning || s == StateStarting }

type Status struct {
	State    State
	Endpoint string // host:port reachable by the UI backend
	// PublicHost is the host[:port] registry clients use, when it differs from Endpoint
	// (e.g. a Route or Ingress host). Empty means clients use Endpoint.
	PublicHost string
}

// ToolVolume is a persistent cache volume shared between runs of a tool (e.g. a scanner's
// vulnerability database). Runtimes without persistent caches may use scratch space instead.
type ToolVolume struct {
	Name string // stable id, e.g. "grype-db"
	Dest string // mount path inside the container
}

// ToolMount bind-mounts a host path. Only runtimes with a shared host filesystem support it.
type ToolMount struct {
	Host, Dest string
	ReadOnly   bool
}

// ToolSpec describes a one-off tool container (scanner, signer, ...).
type ToolSpec struct {
	Image   string
	Args    []string          // appended to the image's entrypoint
	Env     map[string]string // secrets go here, never in Args (argv is visible to other processes)
	Volumes []ToolVolume
	Mounts  []ToolMount
	// HostNetwork lets the tool reach registries published on the manager's own host (podman).
	HostNetwork bool
	// Root runs the tool as container root. On rootless podman that is still the invoking user.
	Root bool
	// Caps are added on top of "drop all" (e.g. SYS_CHROOT).
	Caps    []string
	Timeout time.Duration
}

// ToolResult is what a finished tool produced. Stderr is empty on runtimes that merge streams.
type ToolResult struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// Driver manages the lifecycle of registry instances.
type Driver interface {
	// Create provisions storage and the workload; it does not start it.
	Create(ctx context.Context, s Spec) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	// Delete removes the workload; removeData also deletes persistent storage.
	Delete(ctx context.Context, name string, removeData bool) error
	Status(ctx context.Context, name string) (Status, error)
	// RunGC runs `garbage-collect` against the instance's storage. Instance must be stopped.
	RunGC(ctx context.Context, name string) (output string, err error)
	// UsedBytes reports data volume usage.
	UsedBytes(ctx context.Context, name string) (int64, error)
	// RunTool runs a tool container to completion and returns its output. A non-zero exit code
	// is reported in the result, not as an error. It returns ErrUnsupported when the runtime
	// cannot honour the spec (e.g. host mounts on Kubernetes).
	RunTool(ctx context.Context, spec ToolSpec) (ToolResult, error)
}

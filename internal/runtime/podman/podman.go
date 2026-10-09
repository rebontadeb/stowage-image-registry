// Package podman implements runtime.Driver using the libpod REST API over a unix socket.
package podman

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

const (
	apiBase    = "http://d/v5.0.0/libpod"
	dataTarget = "/var/lib/registry"
)

type Driver struct {
	http     *http.Client
	stateDir string // host dir holding per-instance files
}

// New connects to the podman socket (e.g. $XDG_RUNTIME_DIR/podman/podman.sock).
func New(socketPath, stateDir string) *Driver {
	return &Driver{
		stateDir: stateDir,
		http: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		}},
	}
}

func DefaultSocket() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "podman", "podman.sock")
	}
	return "/run/podman/podman.sock"
}

type mountRec struct {
	Host string `json:"host"`
	Dest string `json:"dest"`
}

type meta struct {
	Image    string     `json:"image"`
	HostPort int        `json:"hostPort"`
	Mounts   []mountRec `json:"mounts"`
}

func volName(name string) string { return "reg-" + name + "-data" }
func ctrName(name string) string { return "reg-" + name }

func (d *Driver) do(ctx context.Context, method, path string, q url.Values, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := apiBase + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

func (d *Driver) expect(ctx context.Context, method, path string, q url.Values, body any, ok ...int) ([]byte, error) {
	code, out, err := d.do(ctx, method, path, q, body)
	if err != nil {
		return nil, err
	}
	for _, c := range ok {
		if code == c {
			return out, nil
		}
	}
	if code == http.StatusNotFound {
		return nil, runtime.ErrNotFound
	}
	return nil, fmt.Errorf("podman %s %s: %d: %s", method, path, code, bytes.TrimSpace(out))
}

func (d *Driver) metaPath(name string) string {
	return filepath.Join(d.stateDir, name, "meta.json")
}

func (d *Driver) loadMeta(name string) (meta, error) {
	var m meta
	b, err := os.ReadFile(d.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return m, runtime.ErrNotFound
		}
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func mountSpecs(m []mountRec) []map[string]any {
	var out []map[string]any
	for _, r := range m {
		out = append(out, map[string]any{
			"type": "bind", "source": r.Host, "destination": r.Dest,
			"options": []string{"ro", "z"},
		})
	}
	return out
}

// pullMu serialises image pulls, so two first-time requests for the same image do not download it twice.
var pullMu sync.Mutex

// ensureImage makes sure ref is in local storage. The libpod create call does not pull by itself: on a machine
// that has never used the image it answers "not found", which would otherwise surface as a missing registry.
func (d *Driver) ensureImage(ctx context.Context, ref string) error {
	exists := func() (bool, error) {
		code, out, err := d.do(ctx, "GET", "/images/"+ref+"/exists", nil, nil)
		switch {
		case err != nil:
			return false, err
		case code == http.StatusNoContent || code == http.StatusOK:
			return true, nil
		case code == http.StatusNotFound:
			return false, nil
		}
		return false, fmt.Errorf("podman: checking image %s: %d: %s", ref, code, bytes.TrimSpace(out))
	}
	if ok, err := exists(); ok || err != nil {
		return err
	}
	pullMu.Lock()
	defer pullMu.Unlock()
	if ok, err := exists(); ok || err != nil { // pulled by someone else while we waited
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	code, out, err := d.do(ctx, "POST", "/images/pull", url.Values{"reference": {ref}, "quiet": {"true"}}, nil)
	if err != nil {
		return fmt.Errorf("%w: pulling %s: %v", runtime.ErrImage, ref, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("%w: pulling %s failed (%d): %s", runtime.ErrImage, ref, code, firstLine(bytes.TrimSpace(out)))
	}
	// The body is a stream of JSON objects; a failed pull still answers 200 and reports the reason in "error".
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var ev struct {
			Error string `json:"error"`
		}
		if dec.Decode(&ev) != nil {
			break
		}
		if ev.Error != "" {
			return fmt.Errorf("%w: pulling %s failed: %s", runtime.ErrImage, ref, firstLine([]byte(ev.Error)))
		}
	}
	return nil
}

func (d *Driver) Create(ctx context.Context, s runtime.Spec) error {
	if s.Image == "" {
		s.Image = runtime.DefaultImage
	}
	if err := d.ensureImage(ctx, s.Image); err != nil {
		return err
	}
	filesDir := filepath.Join(d.stateDir, s.Name, "files")
	// Drop files from a previous generation (e.g. a removed TLS key) before writing the new set.
	if err := os.RemoveAll(filesDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filesDir, 0o700); err != nil {
		return err
	}
	m := meta{Image: s.Image, HostPort: s.HostPort}
	for i, f := range s.Files {
		host := filepath.Join(filesDir, strconv.Itoa(i))
		mode := fs.FileMode(f.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(host, f.Content, mode); err != nil {
			return err
		}
		m.Mounts = append(m.Mounts, mountRec{Host: host, Dest: f.Path})
	}
	mb, _ := json.Marshal(m)
	if err := os.WriteFile(d.metaPath(s.Name), mb, 0o600); err != nil {
		return err
	}

	if _, err := d.expect(ctx, "POST", "/volumes/create", nil, map[string]any{"Name": volName(s.Name), "IgnoreIfExists": true}, 201, 200); err != nil {
		return err
	}
	spec := map[string]any{
		"name":  ctrName(s.Name),
		"image": s.Image,
		"env":   s.Env,
		"volumes": []map[string]any{{
			"Name": volName(s.Name), "Dest": dataTarget, "Options": []string{"z"},
		}},
		"mounts":       mountSpecs(m.Mounts),
		"portmappings": []map[string]any{{"container_port": 5000, "host_port": s.HostPort, "protocol": "tcp"}},
	}
	_, err := d.expect(ctx, "POST", "/containers/create", nil, spec, 201)
	return err
}

func (d *Driver) Start(ctx context.Context, name string) error {
	_, err := d.expect(ctx, "POST", "/containers/"+ctrName(name)+"/start", nil, nil, 204, 304)
	return err
}

func (d *Driver) Stop(ctx context.Context, name string) error {
	_, err := d.expect(ctx, "POST", "/containers/"+ctrName(name)+"/stop", nil, nil, 204, 304)
	return err
}

func (d *Driver) Delete(ctx context.Context, name string, removeData bool) error {
	q := url.Values{"force": {"true"}}
	if _, err := d.expect(ctx, "DELETE", "/containers/"+ctrName(name), q, nil, 200, 204); err != nil && err != runtime.ErrNotFound {
		return err
	}
	if removeData {
		if _, err := d.expect(ctx, "DELETE", "/volumes/"+volName(name), url.Values{"force": {"true"}}, nil, 204, 200); err != nil && err != runtime.ErrNotFound {
			return err
		}
		return os.RemoveAll(filepath.Join(d.stateDir, name))
	}
	return nil
}

func (d *Driver) Status(ctx context.Context, name string) (runtime.Status, error) {
	m, _ := d.loadMeta(name)
	out, err := d.expect(ctx, "GET", "/containers/"+ctrName(name)+"/json", nil, nil, 200)
	if err == runtime.ErrNotFound {
		return runtime.Status{State: runtime.StateMissing}, nil
	}
	if err != nil {
		return runtime.Status{}, err
	}
	var info struct {
		State struct{ Running bool }
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return runtime.Status{}, err
	}
	st := runtime.Status{State: runtime.StateStopped, Endpoint: fmt.Sprintf("127.0.0.1:%d", m.HostPort)}
	st.PublicHost = st.Endpoint
	if info.State.Running {
		st.State = runtime.StateRunning
	}
	return st, nil
}

func (d *Driver) RunGC(ctx context.Context, name string) (string, error) {
	m, err := d.loadMeta(name)
	if err != nil {
		return "", err
	}
	st, err := d.Status(ctx, name)
	if err != nil {
		return "", err
	}
	if st.State == runtime.StateRunning {
		return "", fmt.Errorf("stop instance %q before garbage collection", name)
	}
	gc := ctrName(name) + "-gc"
	spec := map[string]any{
		"name":  gc,
		"image": m.Image,
		// --delete-untagged also reclaims manifests no tag reaches (children of deleted multi-arch indexes).
		"command": []string{"garbage-collect", "--delete-untagged", "/etc/distribution/config.yml"},
		"volumes": []map[string]any{{"Name": volName(name), "Dest": dataTarget, "Options": []string{"z"}}},
		"mounts":  mountSpecs(m.Mounts),
		"remove":  false,
	}
	if _, err := d.expect(ctx, "POST", "/containers/create", nil, spec, 201); err != nil {
		return "", err
	}
	defer d.expect(context.Background(), "DELETE", "/containers/"+gc, url.Values{"force": {"true"}}, nil, 200, 204)
	if _, err := d.expect(ctx, "POST", "/containers/"+gc+"/start", nil, nil, 204); err != nil {
		return "", err
	}
	var exit int
	out, err := d.expect(ctx, "POST", "/containers/"+gc+"/wait", nil, nil, 200)
	if err != nil {
		return "", err
	}
	_ = json.Unmarshal(out, &exit)
	logs, _ := d.expect(ctx, "GET", "/containers/"+gc+"/logs", url.Values{"stdout": {"true"}, "stderr": {"true"}}, nil, 200)
	text := demux(logs)
	if exit != 0 {
		return text, fmt.Errorf("garbage-collect exited %d", exit)
	}
	return text, nil
}

// UsedBytes asks podman for the volume size (works from inside a container that cannot see the
// volume's host path) and falls back to walking the mount point when running on the host.
func (d *Driver) UsedBytes(ctx context.Context, name string) (int64, error) {
	if n, ok := d.dfSize(ctx, volName(name)); ok {
		return n, nil
	}
	out, err := d.expect(ctx, "GET", "/volumes/"+volName(name)+"/json", nil, nil, 200)
	if err != nil {
		return 0, err
	}
	var v struct{ Mountpoint string }
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, err
	}
	var total int64
	err = filepath.WalkDir(v.Mountpoint, func(_ string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		fi, err := e.Info()
		if err == nil {
			total += fi.Size()
		}
		return err
	})
	return total, err
}

func (d *Driver) dfSize(ctx context.Context, volume string) (int64, bool) {
	out, err := d.expect(ctx, "GET", "/system/df", nil, nil, 200)
	if err != nil {
		return 0, false
	}
	var df struct {
		Volumes []struct {
			VolumeName string
			Size       int64
		}
	}
	if json.Unmarshal(out, &df) != nil {
		return 0, false
	}
	for _, v := range df.Volumes {
		if v.VolumeName == volume {
			return v.Size, true
		}
	}
	return 0, false
}

// splitStreams separates podman's multiplexed log output (8-byte header: stream type, 3 zero
// bytes, big-endian length) into stdout (type 1) and stderr (type 2).
func splitStreams(b []byte) (stdout, stderr []byte) {
	var o, e bytes.Buffer
	for len(b) >= 8 {
		n := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		kind := b[0]
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		if kind == 2 {
			e.Write(b[:n])
		} else {
			o.Write(b[:n])
		}
		b = b[n:]
	}
	return o.Bytes(), e.Bytes()
}

// demux merges both streams, in arrival order is not preserved; used for human-readable logs.
func demux(b []byte) string {
	o, e := splitStreams(b)
	return string(o) + string(e)
}

// RunTool runs a one-off tool container to completion. The container is always removed.
func (d *Driver) RunTool(ctx context.Context, t runtime.ToolSpec) (runtime.ToolResult, error) {
	if t.Timeout <= 0 {
		t.Timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	idb := make([]byte, 6)
	_, _ = rand.Read(idb)
	name := "regui-tool-" + hex.EncodeToString(idb)

	if err := d.ensureImage(ctx, t.Image); err != nil {
		return runtime.ToolResult{}, err
	}
	var vols []map[string]any
	for _, v := range t.Volumes {
		vn := "regui-" + v.Name
		if _, err := d.expect(ctx, "POST", "/volumes/create", nil, map[string]any{"Name": vn, "IgnoreIfExists": true}, 201, 200); err != nil {
			return runtime.ToolResult{}, err
		}
		// U: chown the volume to the container's user so a non-root tool can write its cache.
		vols = append(vols, map[string]any{"Name": vn, "Dest": v.Dest, "Options": []string{"U"}})
	}
	var mounts []map[string]any
	for _, m := range t.Mounts {
		opts := []string{}
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		mounts = append(mounts, map[string]any{"type": "bind", "source": m.Host, "destination": m.Dest, "options": opts})
	}
	spec := map[string]any{
		"name": name, "image": t.Image, "command": t.Args, "env": t.Env,
		"volumes": vols, "mounts": mounts,
		"cap_drop":          []string{"ALL"},
		"cap_add":           t.Caps,
		"no_new_privileges": true,
		"labels":            map[string]string{"registry-ui": "tool"},
		"resource_limits": map[string]any{
			"memory": map[string]any{"limit": int64(4) << 30},
			"pids":   map[string]any{"limit": 1024},
		},
	}
	if len(t.Mounts) > 0 {
		// Relabelling a whole unpacked image for SELinux can take minutes; run this one tool
		// without label separation instead (it is still unprivileged, capability-dropped, no-new-privs).
		spec["selinux_opts"] = []string{"disable"}
	}
	if t.HostNetwork {
		spec["netns"] = map[string]any{"nsmode": "host"}
	}
	if t.Root {
		spec["user"] = "0"
	}
	if _, err := d.expect(ctx, "POST", "/containers/create", nil, spec, 201); err != nil {
		return runtime.ToolResult{}, err
	}
	defer func() { // not the request context: it may be cancelled, and we must not leak containers
		cctx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_, _ = d.expect(cctx, "DELETE", "/containers/"+name, url.Values{"force": {"true"}}, nil, 200, 204)
	}()
	if _, err := d.expect(ctx, "POST", "/containers/"+name+"/start", nil, nil, 204); err != nil {
		return runtime.ToolResult{}, err
	}
	out, err := d.expect(ctx, "POST", "/containers/"+name+"/wait", nil, nil, 200)
	if err != nil {
		if ctx.Err() != nil {
			return runtime.ToolResult{}, fmt.Errorf("tool timed out after %s", t.Timeout)
		}
		return runtime.ToolResult{}, err
	}
	var code int
	_ = json.Unmarshal(out, &code)
	logs, err := d.expect(ctx, "GET", "/containers/"+name+"/logs", url.Values{"stdout": {"true"}, "stderr": {"true"}}, nil, 200)
	if err != nil {
		return runtime.ToolResult{}, err
	}
	so, se := splitStreams(logs)
	return runtime.ToolResult{Stdout: so, Stderr: se, ExitCode: code}, nil
}

var _ runtime.Driver = (*Driver)(nil)

func firstLine(b []byte) string {
	s := string(b)
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		s = string(b[:i])
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

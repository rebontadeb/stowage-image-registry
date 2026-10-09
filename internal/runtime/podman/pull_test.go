package podman

import (
	"context"
	"os"
	"testing"
	"time"
)

// Needs a podman socket: STOWAGE_PODMAN_SOCKET=/run/user/1000/podman/podman.sock go test ./internal/runtime/podman
func TestEnsureImagePullsWhatIsMissingAndReportsFailures(t *testing.T) {
	sock := os.Getenv("STOWAGE_PODMAN_SOCKET")
	if sock == "" {
		t.Skip("set STOWAGE_PODMAN_SOCKET to run against a real podman")
	}
	d := New(sock, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const ref = "docker.io/library/hello-world:latest"
	// Never remove an image the machine already had: only run when the test itself is the one that pulls it.
	if code, _, _ := d.do(ctx, "GET", "/images/"+ref+"/exists", nil, nil); code != 404 {
		t.Skipf("%s is already on this machine (exists answered %d); not touching it", ref, code)
	}
	if err := d.ensureImage(ctx, ref); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if code, _, _ := d.do(ctx, "GET", "/images/"+ref+"/exists", nil, nil); code != 204 {
		t.Fatalf("image should exist after ensureImage, answered %d", code)
	}
	if err := d.ensureImage(ctx, ref); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
	_, _, _ = d.do(ctx, "DELETE", "/images/"+ref, nil, nil)

	if err := d.ensureImage(ctx, "docker.io/library/stowage-no-such-image-xyz:1"); err == nil {
		t.Fatal("a missing image must be an error, not a silent success")
	}
}

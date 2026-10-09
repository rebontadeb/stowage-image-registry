// Smoke CLI (milestone 1): create/start/status/stop/gc/delete a registry via the podman driver.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/runtime/podman"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: server <create|start|stop|status|gc|usage|delete> <name> [port]")
		os.Exit(2)
	}
	home, _ := os.UserHomeDir()
	d := podman.New(podman.DefaultSocket(), home+"/.local/share/registry-ui")
	ctx := context.Background()
	cmd, name := os.Args[1], os.Args[2]

	var err error
	switch cmd {
	case "create":
		port := 5000
		if len(os.Args) > 3 {
			port, _ = strconv.Atoi(os.Args[3])
		}
		err = d.Create(ctx, runtime.Spec{Name: name, HostPort: port})
	case "start":
		err = d.Start(ctx, name)
	case "stop":
		err = d.Stop(ctx, name)
	case "status":
		var st runtime.Status
		st, err = d.Status(ctx, name)
		fmt.Printf("%+v\n", st)
	case "gc":
		var out string
		out, err = d.RunGC(ctx, name)
		fmt.Println(out)
	case "usage":
		var n int64
		n, err = d.UsedBytes(ctx, name)
		fmt.Println(n, "bytes")
	case "delete":
		err = d.Delete(ctx, name, true)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

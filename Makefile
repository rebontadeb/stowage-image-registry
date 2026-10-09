GO_IMAGE ?= registry.access.redhat.com/hi/go:latest
# Go build and module caches live outside the project (it may be synced, and the caches are ~2 GB).
GO_CACHE ?= $(HOME)/.cache/registry-ui-go
GO := podman run --rm -v $(CURDIR):/src:z -v $(GO_CACHE):/gocache:z -w /src -e GOCACHE=/gocache/go-build -e GOMODCACHE=/gocache/go-mod -e GOFLAGS=-buildvcs=false $(GO_IMAGE) go

UI_SRC := $(shell find web/src web/index.html web/package.json web/vite.config.ts -type f 2>/dev/null)

.PHONY: ui vet build test clean podman-image
ui: web/dist/index.html
web/dist/index.html: $(UI_SRC)
	cd web && npm ci --silent && npm run build

# Go packages embed web/dist, so the UI must exist first.
vet: ui
	@mkdir -p $(GO_CACHE)
	$(GO) vet ./...
build: ui
	@mkdir -p $(GO_CACHE)
	$(GO) build -o bin/server ./cmd/server
test: ui
	@mkdir -p $(GO_CACHE)
	$(GO) test ./...
clean:
	rm -rf bin web/dist

# The manager as a container image (also what Kubernetes deploys). Runs on podman too: see README.
podman-image:
	podman build -f deploy/Containerfile -t localhost/registry-ui:latest .

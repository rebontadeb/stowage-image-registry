// Command server runs the registry manager: REST API, embedded UI, sign-in and audit.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/rdeb/local-image-registry/internal/api"
	"github.com/rdeb/local-image-registry/internal/auth"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/runtime/fake"
	"github.com/rdeb/local-image-registry/internal/runtime/kubernetes"
	"github.com/rdeb/local-image-registry/internal/runtime/podman"
	"github.com/rdeb/local-image-registry/internal/service"
	"github.com/rdeb/local-image-registry/internal/store"
	"github.com/rdeb/local-image-registry/internal/vault"
	"github.com/rdeb/local-image-registry/web"
)

func csv(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// version is set at build time: -ldflags "-X main.version=..." (see the Makefile and deploy/Containerfile).
var version = "dev"

func main() {
	home, _ := os.UserHomeDir()
	listen := flag.String("listen", "127.0.0.1:8080", "API and UI listen address")
	dataDir := flag.String("data-dir", filepath.Join(home, ".local/share/registry-ui"), "state directory")
	socket := flag.String("podman-socket", podman.DefaultSocket(), "podman API socket")
	portMin := flag.Int("port-min", 5100, "first registry host port (podman; also used as a unique id on kubernetes)")
	portMax := flag.Int("port-max", 5999, "last registry host port")
	rt := flag.String("runtime", "podman", "container runtime: podman, kubernetes or fake (UI development)")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig path (default: in-cluster, then ~/.kube/config)")
	k8sNS := flag.String("k8s-namespace", "", "namespace for registries (default: the pod's own namespace)")
	k8sSC := flag.String("k8s-storage-class", "", "StorageClass for registry volumes (default: cluster default)")
	k8sExpose := flag.String("k8s-expose", "", "external access: '', route (OpenShift) or ingress")
	k8sDomain := flag.String("k8s-domain", "", "base domain; registries get <name>.<domain> (needed with -k8s-expose)")
	k8sIngressClass := flag.String("k8s-ingress-class", "", "ingress class name")
	k8sIngressTLS := flag.String("k8s-ingress-tls-secret", "", "TLS secret for ingress hosts")
	k8sFSGroup := flag.Int64("k8s-fsgroup", 0, "pod fsGroup; leave 0 on OpenShift")

	trustProxy := flag.Bool("trust-proxy", false, "take client addresses from X-Forwarded-For (only behind a proxy you control)")
	noLocal := flag.Bool("disable-local-login", false, "allow single sign-on only")
	auditDays := flag.Int("audit-retention-days", 365, "delete audit entries older than this")
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL; enables single sign-on")
	oidcClient := flag.String("oidc-client-id", "", "OIDC client id")
	oidcRedirect := flag.String("oidc-redirect-url", "", "OIDC redirect URL: https://<this host>/api/auth/oidc/callback")
	oidcName := flag.String("oidc-name", "single sign-on", "label for the sign-in button")
	oidcGroupsClaim := flag.String("oidc-groups-claim", "groups", "ID token claim holding the user's groups")
	oidcAdmin := flag.String("oidc-admin-groups", "", "comma separated groups that map to the admin role")
	oidcOperator := flag.String("oidc-operator-groups", "", "comma separated groups that map to the operator role")
	oidcViewer := flag.String("oidc-viewer-groups", "", "comma separated groups that map to the viewer role")
	oidcDefault := flag.String("oidc-default-role", "", "role for users in no mapped group (default: deny)")

	importGiB := flag.Int("import-max-gib", 8, "largest image (GiB) that Add image may import or upload")
	secOn := flag.Bool("security", true, "enable vulnerability scanning, SBOMs, signing and compliance checks")
	scanWorkers := flag.Int("scan-workers", 2, "concurrent scan jobs")
	defImg := service.DefaultToolImages()
	imgSyft := flag.String("tool-syft-image", defImg.Syft, "syft image (SBOMs)")
	imgGrype := flag.String("tool-grype-image", defImg.Grype, "grype image (vulnerability scans)")
	imgCosign := flag.String("tool-cosign-image", defImg.Cosign, "cosign image (signatures)")
	imgOscap := flag.String("tool-openscap-image", defImg.OpenSCAP, "openscap image (OVAL compliance checks)")
	imgFix := flag.String("tool-fix-image", "registry.access.redhat.com/ubi%s/ubi-minimal:latest", "image with microdnf that patches packages in Fix (%s = RHEL major version)")
	imgFixAlpine := flag.String("tool-fix-alpine-image", "docker.io/library/alpine:%s", "image with apk that patches packages of Alpine images in Fix (%s = Alpine release, e.g. 3.14)")
	imgFixDebian := flag.String("tool-fix-debian-image", "registry.access.redhat.com/ubi9/ubi-minimal:latest", "image with a shell and chroot used by Fix for Debian and Ubuntu images")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	fatal := func(msg string, args ...any) { log.Error(msg, args...); os.Exit(1) }

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fatal("data dir", "err", err)
	}
	st, err := store.Open(filepath.Join(*dataDir, "registry-ui.db"))
	if err != nil {
		fatal("open store", "err", err)
	}
	defer st.Close()

	var drv runtime.Driver
	fakeRuntime := false
	switch *rt {
	case "podman":
		drv = podman.New(*socket, filepath.Join(*dataDir, "instances"))
	case "kubernetes":
		d, err := kubernetes.Connect(*kubeconfig, kubernetes.Config{
			Namespace: *k8sNS, StorageClass: *k8sSC, Expose: kubernetes.Expose(*k8sExpose), Domain: *k8sDomain,
			IngressClass: *k8sIngressClass, IngressTLSSecret: *k8sIngressTLS, FSGroup: *k8sFSGroup,
		})
		if err != nil {
			fatal("kubernetes", "err", err)
		}
		drv = d
	case "fake":
		drv, fakeRuntime = fake.New(), true
	default:
		fatal("unknown -runtime", "value", *rt)
	}
	svc := service.New(st, drv, *portMin, *portMax)
	if fakeRuntime {
		svc.SetReadyTimeout(0)
	}
	svc.SetImportLimit(int64(*importGiB) << 30)
	svc.SetScratchDir(filepath.Join(*dataDir, "scratch"))

	if *secOn {
		v, err := vault.Load(*dataDir, os.Getenv("REGISTRY_UI_MASTER_KEY"))
		if err != nil {
			fatal("master key", "err", err)
		}
		if err := svc.EnableSecurity(service.SecurityConfig{
			Vault: v, DataDir: *dataDir, Workers: *scanWorkers,
			Images:   service.ToolImages{Syft: *imgSyft, Grype: *imgGrype, Cosign: *imgCosign, OpenSCAP: *imgOscap},
			FixImage: *imgFix, FixAlpineImage: *imgFixAlpine, FixDebianImage: *imgFixDebian,
		}); err != nil {
			fatal("security", "err", err)
		}
		defer svc.Close()
	}

	authSvc := auth.NewService(st)
	adminUser := os.Getenv("REGISTRY_UI_ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}
	generated, created, err := authSvc.Bootstrap(adminUser, os.Getenv("REGISTRY_UI_ADMIN_PASSWORD"))
	if err != nil {
		fatal("bootstrap admin", "err", err)
	}
	if created && generated != "" {
		// Printed once, never stored in clear. The account must change it at first sign-in.
		log.Warn("created first admin account", "username", adminUser, "password", generated, "note", "change it at first sign-in")
	} else if created {
		log.Info("created first admin account", "username", adminUser)
	}

	var oidc *auth.OIDC
	if *oidcIssuer != "" {
		oidc, err = auth.NewOIDC(auth.OIDCConfig{
			Issuer: *oidcIssuer, ClientID: *oidcClient, ClientSecret: os.Getenv("REGISTRY_UI_OIDC_CLIENT_SECRET"),
			RedirectURL: *oidcRedirect, DisplayName: *oidcName, GroupsClaim: *oidcGroupsClaim,
			AdminGroups: csv(*oidcAdmin), OperatorGroups: csv(*oidcOperator), ViewerGroups: csv(*oidcViewer),
			DefaultRole: auth.Role(*oidcDefault),
		})
		if err != nil {
			fatal("oidc", "err", err)
		}
	}
	if *noLocal && oidc == nil {
		fatal("-disable-local-login needs OIDC configured, or nobody could sign in")
	}

	purge := func() {
		_ = st.PurgeSessions()
		if n, err := st.PurgeAudit(time.Now().AddDate(0, 0, -*auditDays)); err == nil && n > 0 {
			log.Info("purged old audit entries", "count", n)
		}
	}
	purge()
	go func() {
		for range time.Tick(6 * time.Hour) {
			purge()
		}
	}()

	root := http.NewServeMux()
	root.Handle("/api/", api.New(svc, api.Options{
		Auth: authSvc, OIDC: oidc, Store: st, DisableLocalLogin: *noLocal, TrustProxy: *trustProxy, Version: version, Log: log,
	}))
	root.Handle("/", web.Handler())
	srv := &http.Server{Addr: *listen, Handler: api.Secure(root), ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "version", version, "addr", *listen, "runtime", *rt, "security", *secOn, "sso", oidc != nil, "localLogin", !*noLocal)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

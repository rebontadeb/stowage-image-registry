package service

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	gort "runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/rdeb/local-image-registry/internal/imgfs"
	"github.com/rdeb/local-image-registry/internal/regclient"
	"github.com/rdeb/local-image-registry/internal/runtime"
	"github.com/rdeb/local-image-registry/internal/scanparse"
	"github.com/rdeb/local-image-registry/internal/store"
)

// ErrNothingToFix means the scan found no vulnerability that a package update resolves.
var ErrNothingToFix = errors.New("nothing to fix")

var (
	pkgRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	majorRe = regexp.MustCompile(`^[0-9]{1,2}$`)
)

// FixPlan lists what a fix would change, for the confirmation dialog.
type FixPlan struct {
	Packages []string `json:"packages"` // empty with All set: every package that has an update
	All      bool     `json:"all"`
	Manager  string   `json:"manager"` // "dnf" (RHEL/UBI) or "apk" (Alpine)
	NewTag   string   `json:"newTag"`
}

// osPackageType is what grype calls the packages of each manager Fix supports.
var osPackageType = map[string]string{"dnf": "rpm", "apk": "apk", "apt": "deb"}

// fixManager picks the package manager from the kinds of package the scan found: OS packages only.
func fixManager(rep scanparse.VulnReport) string {
	n := map[string]int{}
	for _, v := range rep.Vulns {
		n[v.Type]++
	}
	best, most := "", 0
	for _, m := range []string{"dnf", "apk", "apt"} { // ties go to the earlier one
		if c := n[osPackageType[m]]; c > most {
			best, most = m, c
		}
	}
	return best
}

// fixablePackages returns the names of OS packages of the given type with a known fixed version.
func fixablePackages(rep scanparse.VulnReport, typ string) []string {
	set := map[string]bool{}
	for _, v := range rep.Vulns {
		if v.Type == typ && len(v.FixedIn) > 0 && pkgRe.MatchString(v.Package) {
			set[v.Package] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (s *Service) fixInputs(ctx context.Context, registry, repo, ref, tag string) (digest, newTag, manager string, pkgs []string, err error) {
	if s.sec == nil {
		return "", "", "", nil, ErrSecurityDisabled
	}
	if !regclient.ValidRepo(repo) {
		return "", "", "", nil, fmt.Errorf("%w: invalid repository name", ErrInvalid)
	}
	c, err := s.client(ctx, registry)
	if err != nil {
		return "", "", "", nil, err
	}
	digest = ref
	if !digestRe.MatchString(ref) {
		if digest, err = c.Digest(ctx, repo, ref); err != nil {
			return "", "", "", nil, mapReg(err)
		}
	}
	if !digestRe.MatchString(digest) {
		return "", "", "", nil, fmt.Errorf("%w: registry returned an unusable digest", ErrInvalid)
	}
	newTag = tag
	if newTag == "" {
		if digestRe.MatchString(ref) {
			return "", "", "", nil, fmt.Errorf("%w: give the new tag for the fixed image", ErrInvalid)
		}
		newTag = ref + "-fixed"
	}
	if !tagRe.MatchString(newTag) {
		return "", "", "", nil, fmt.Errorf("%w: invalid tag", ErrInvalid)
	}
	if newTag == ref {
		return "", "", "", nil, fmt.Errorf("%w: the fixed image needs a different tag than the original", ErrInvalid)
	}
	sc, err := s.scan(registry, repo, digest, KindVuln)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", "", "", nil, fmt.Errorf("%w: scan this image for vulnerabilities first", ErrNotReady)
		}
		return "", "", "", nil, err
	}
	raw, err := gunzip(sc.Result)
	if err != nil {
		return "", "", "", nil, err
	}
	var rep scanparse.VulnReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return "", "", "", nil, err
	}
	if rep.Summary.Total == 0 {
		return "", "", "", nil, fmt.Errorf("%w: the scan found no vulnerabilities", ErrNothingToFix)
	}
	manager = fixManager(rep)
	if manager == "" {
		return "", "", "", nil, fmt.Errorf("%w: none of the findings is in an operating-system package (RPM or Alpine apk); application dependencies cannot be fixed here", ErrNothingToFix)
	}
	// Advisories often carry no fixed version (Red Hat marks many as "not-fixed" until errata are matched),
	// so when nothing is individually fixable the plan is to update every package that has an update.
	return digest, newTag, manager, fixablePackages(rep, osPackageType[manager]), nil
}

// PlanFix reports what FixImage would do, without doing it.
func (s *Service) PlanFix(ctx context.Context, registry, repo, ref, tag string) (FixPlan, error) {
	_, newTag, mgr, pkgs, err := s.fixInputs(ctx, registry, repo, ref, tag)
	return FixPlan{Packages: pkgs, All: err == nil && len(pkgs) == 0, Manager: mgr, NewTag: newTag}, err
}

// FixImage patches the fixable OS packages of an image and pushes the result as a new tag.
// The original is not modified. The new image is scanned when done.
func (s *Service) FixImage(ctx context.Context, registry, repo, ref, tag, by string) (TransferView, error) {
	digest, newTag, mgr, pkgs, err := s.fixInputs(ctx, registry, repo, ref, tag)
	if err != nil {
		return TransferView{}, err
	}
	a, err := s.prepare(ctx, registry, repo, newTag, true) // re-running a fix replaces the earlier -fixed tag
	if err != nil {
		return TransferView{}, err
	}
	job, err := s.tr.newJob("fix", registry, repo, newTag, repo+"@"+digest[:19], by)
	if err != nil {
		return TransferView{}, err
	}
	view := *job
	go s.run(job.ID, true, func(ctx context.Context, progress func(done, total int64)) (string, error) {
		return s.doFix(ctx, a, repo, digest, newTag, mgr, pkgs, progress)
	})
	return view, nil
}

func (s *Service) doFix(ctx context.Context, a access, repo, digest, newTag, mgr string, pkgs []string, progress func(done, total int64)) (string, error) {
	s.sec.fix.Lock()
	defer s.sec.fix.Unlock()
	scratch, err := os.MkdirTemp(filepath.Join(s.sec.cfg.DataDir, "scratch"), "fix-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(scratch)
	rootfs := filepath.Join(scratch, "root")
	if err := s.sec.pull(ctx, imgfs.Source{Ref: a.ref(repo, digest), Username: a.user, Password: a.pass, HTTP: !a.tls, SkipTLS: a.tls}, rootfs); err != nil {
		return "", errors.New(redact(err.Error(), a.pass))
	}
	kv := readOSReleaseKV(rootfs)
	spec, applied, err := s.fixTool(mgr, kv, rootfs, pkgs)
	if err != nil {
		return "", err
	}
	before, err := imgfs.TakeSnapshot(rootfs)
	if err != nil {
		return "", err
	}
	res, err := s.drv.RunTool(ctx, spec)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		if mgr == "apt" {
			if msg := aptErrors(res); msg != "" {
				return "", fmt.Errorf("apt failed (exit %d): %s", res.ExitCode, msg)
			}
		}
		return "", toolFailure(mgr, res)
	}
	if n := applied(res.Stdout); n == 0 {
		return "", fmt.Errorf("%w: the package repositories have no newer packages for this image", ErrNothingToFix)
	}

	tmp, err := os.Create(filepath.Join(scratch, "fix.tar.gz"))
	if err != nil {
		return "", err
	}
	zw := gzip.NewWriter(tmp)
	n, err := imgfs.WriteLayer(rootfs, before, zw)
	if err == nil {
		err = zw.Close()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("%w: the update changed no files", ErrNothingToFix)
	}
	layer, err := tarball.LayerFromFile(tmp.Name())
	if err != nil {
		return "", err
	}

	src, err := s.sourceImage(ctx, a, repo, digest)
	if err != nil {
		return "", err
	}
	img, err := mutate.Append(src, mutate.Addendum{
		Layer:   layer,
		History: v1.History{Created: v1.Time{Time: time.Now().UTC()}, CreatedBy: "stowage fix: " + mgr + " upgrade " + strings.Join(pkgs, " ") + map[bool]string{true: "(all packages)"}[len(pkgs) == 0], Comment: "fixed from " + digest},
	})
	if err != nil {
		return "", err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return "", err
	}
	cfg = cfg.DeepCopy()
	if cfg.Config.Labels == nil {
		cfg.Config.Labels = map[string]string{}
	}
	cfg.Config.Labels["io.stowage.fixed-from"] = digest
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		return "", err
	}
	size, err := imageSize(img)
	if err != nil {
		return "", err
	}
	if size > s.tr.limit {
		return "", fmt.Errorf("%w: the fixed image is %s, above the %s limit", ErrInvalid, humanBytes(size), humanBytes(s.tr.limit))
	}

	dst, dstOpts, err := s.destination(a, repo, newTag)
	if err != nil {
		return "", err
	}
	progOpt, stop := pushProgress(progress)
	defer stop()
	if err := remote.Write(dst, img, append(dstOpts, remote.WithContext(ctx), progOpt)...); err != nil {
		return "", err
	}
	d, err := img.Digest()
	return d.String(), err
}

var (
	upgradingRe = regexp.MustCompile(`Upgrading:\s+([0-9]+) packages`)
	apkUpgrade  = regexp.MustCompile(`(?m)^\([0-9]+/[0-9]+\) Upgrading `)
	alpineRe    = regexp.MustCompile(`^([0-9]+\.[0-9]+)`)
	aptUpgraded = regexp.MustCompile(`(?m)^([0-9]+) upgraded,`)
)

// aptScript upgrades the given packages (all of them when none are given) with the image's own apt, in a chroot of
// the unpacked image. Package names arrive as arguments, never inside the script text.
const aptScript = `set -u
R=/rootfs
added=0
# The unpacked tree keeps owner-only modes; apt needs a usable /tmp, and runs its downloads as root because the
# unprivileged _apt user does not exist in this user namespace. Fresh indexes are mandatory: stale ones are an error.
chmod 1777 "$R/tmp" 2>/dev/null
# Unpacking gave every file today's modification time, so apt would take the image's old package lists for
# current ones (the mirror answers "not modified"). Start from nothing.
rm -rf "$R"/var/lib/apt/lists/*
if [ ! -e "$R/etc/resolv.conf" ]; then cp /etc/resolv.conf "$R/etc/resolv.conf" && added=1; fi
chroot "$R" env DEBIAN_FRONTEND=noninteractive sh -c '
  O="-o APT::Sandbox::User=root -o Dpkg::Options::=--force-confold"
  apt-get $O -o APT::Update::Error-Mode=any update -qq || exit 1
  if [ "$#" -gt 0 ]; then apt-get -y $O --only-upgrade install "$@"
  else apt-get -y $O upgrade; fi' sh "$@"
rc=$?
chroot "$R" apt-get clean >/dev/null 2>&1
rm -rf "$R"/var/lib/apt/lists/*
[ "$added" = 1 ] && rm -f "$R/etc/resolv.conf"
exit $rc`

// fixTool builds the tool container that updates the unpacked image at rootfs, and a function that
// counts the packages its output says were upgraded.
func (s *Service) fixTool(mgr string, osr map[string]string, rootfs string, pkgs []string) (runtime.ToolSpec, func([]byte) int, error) {
	id := osr["ID"]
	spec := runtime.ToolSpec{
		Mounts: []runtime.ToolMount{{Host: rootfs, Dest: "/rootfs"}},
		// Package managers change ownership and modes and run scriptlets in a chroot. Container root in a
		// rootless user namespace is still the invoking user on the host.
		Root: true, Caps: []string{"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "SETUID", "SETGID", "SETFCAP", "SYS_CHROOT", "KILL"},
		Timeout: 20 * time.Minute,
	}
	switch {
	case mgr == "dnf" && id == "rhel":
		major, _, _ := strings.Cut(osr["VERSION_ID"], ".")
		if !majorRe.MatchString(major) {
			return spec, nil, fmt.Errorf("%w: cannot tell which RHEL release this image is", ErrInvalid)
		}
		spec.Image = fmt.Sprintf(s.sec.cfg.FixImage, major)
		spec.Args = append([]string{"microdnf", "-y", "--installroot=/rootfs", "--config=/etc/dnf/dnf.conf", "--noplugins",
			"--setopt=cachedir=/tmp/cache", "--setopt=reposdir=/etc/yum.repos.d", "--setopt=varsdir=/etc/dnf/vars",
			"--setopt=install_weak_deps=0", "--releasever=" + major, "upgrade"}, pkgs...)
		return spec, func(out []byte) int {
			if m := upgradingRe.FindSubmatch(out); m != nil {
				n, _ := strconv.Atoi(string(m[1]))
				return n
			}
			return 0
		}, nil
	case mgr == "apk" && id == "alpine":
		m := alpineRe.FindStringSubmatch(osr["VERSION_ID"])
		if m == nil {
			return spec, nil, fmt.Errorf("%w: cannot tell which Alpine release this image is", ErrInvalid)
		}
		spec.Image = fmt.Sprintf(s.sec.cfg.FixAlpineImage, m[1])
		// The image's own repositories and keys are used, so the packages come from the release it was built for.
		spec.Args = append([]string{"apk", "--root", "/rootfs", "--no-cache", "upgrade"}, pkgs...)
		return spec, func(out []byte) int { return len(apkUpgrade.FindAll(out, -1)) }, nil
	case mgr == "apt" && (id == "debian" || id == "ubuntu"):
		// The image's own apt runs in a chroot of the unpacked root, so packages come from the repositories the
		// image was built for. The helper only needs chroot and a shell, and the network.
		spec.Image = s.sec.cfg.FixDebianImage
		spec.Args = append([]string{"sh", "-c", aptScript, "sh"}, pkgs...)
		return spec, func(out []byte) int {
			if m := aptUpgraded.FindSubmatch(out); m != nil {
				n, _ := strconv.Atoi(string(m[1]))
				return n
			}
			return 0
		}, nil
	}
	return spec, nil, fmt.Errorf("%w: this image is %q, but its findings are in %s packages; only RHEL/UBI (RPM), Alpine (apk) and Debian/Ubuntu (apt) images can be fixed", ErrInvalid, osr["PRETTY_NAME"], mgr)
}

// sourceImage reads the original image from the managed registry, for this host's platform.
func (s *Service) sourceImage(ctx context.Context, a access, repo, digest string) (v1.Image, error) {
	ref, opts, err := s.destination(a, repo, "latest") // same transport and credentials
	if err != nil {
		return nil, err
	}
	d, err := name.NewDigest(ref.Context().Name()+"@"+digest, name.WeakValidation)
	if err != nil {
		return nil, err
	}
	if !a.tls {
		d, err = name.NewDigest(ref.Context().Name()+"@"+digest, name.WeakValidation, name.Insecure)
		if err != nil {
			return nil, err
		}
	}
	opts = append(opts, remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: gort.GOARCH}))
	return remote.Image(d, opts...)
}

// aptErrors collects the "E:" lines of apt's output: the part of a long log that says what went wrong.
func aptErrors(res runtime.ToolResult) string {
	var out []string
	for _, line := range strings.Split(string(res.Stderr)+"\n"+string(res.Stdout), "\n") {
		if strings.HasPrefix(line, "E: ") {
			if out = append(out, strings.TrimSpace(line[3:])); len(out) == 6 {
				break
			}
		}
	}
	msg := strings.Join(out, "; ")
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	return msg
}

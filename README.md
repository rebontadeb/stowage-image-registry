# Stowage

Private container registries for your tenants: a UI and API that gives each tenant an isolated registry. Every
registry is an isolated `distribution` instance with its own users, TLS and storage. It also scans images for
vulnerabilities, lists their contents (SBOM), signs them, and can patch or rebase them. Runs on **podman** today
and on **Kubernetes / OpenShift** with the same code (runtime driver interface).

* [Run it on a new machine](#run-it-on-a-new-machine)
* [Configuration reference](#configuration-reference)
* [Operating it: data, backup, upgrade, uninstall](#operating-it-data-backup-upgrade-uninstall)
* [Troubleshooting](#troubleshooting)
* Features: [roles](#who-can-do-what), [sign-in](#sign-in), [adding images](#adding-images-from-the-ui),
  [security tools](#image-security-scans-sboms-signatures-red-hat-oval), [Kubernetes](#kubernetes--openshift)

## Run it on a new machine

### What you need

| Need | Details |
|---|---|
| OS | Linux (x86-64 or arm64). Developed and tested on Fedora with rootless podman. macOS and Windows (podman machine) are untested. |
| podman | 5.x (developed and tested with 5.8), **rootless**, with its API socket: `systemctl --user enable --now podman.socket` |
| git | to fetch the code |
| Internet | to pull base images on the first build and first use (see below). Air-gapped installs need a mirror. |
| Free ports | the UI port (default 18080 in the container recipe, 8080 for the plain binary) and **5100-5999** on the host: each tenant registry gets one |
| Disk | a few GB for images and tool caches, plus whatever your tenants store |

You do **not** need Go or Node installed: the container recipe builds everything inside containers.

Check podman works rootless before you start:

```sh
podman --version
podman info --format '{{.Host.Security.Rootless}}'      # should print true
systemctl --user enable --now podman.socket
ls "$XDG_RUNTIME_DIR/podman/podman.sock"                  # the socket must exist
```

If `XDG_RUNTIME_DIR` is empty (for example over a bare `su`), log in again with a normal session, or run
`export XDG_RUNTIME_DIR=/run/user/$(id -u)`.

### Option A (recommended): run Stowage as a container

```sh
git clone git@github.com:rebontadeb/stowage-image-registry.git
cd stowage-image-registry

make podman-image                  # builds localhost/registry-ui:latest (UI + Go binary, all in containers)

mkdir -p ~/.local/share/registry-ui
podman run -d --name registry-ui \
  --network host --userns keep-id --user "$(id -u):$(id -g)" --security-opt label=disable \
  -v "$XDG_RUNTIME_DIR/podman/podman.sock:/run/podman/podman.sock" \
  -v "$HOME/.local/share/registry-ui:$HOME/.local/share/registry-ui" \
  -e REGISTRY_UI_ADMIN_PASSWORD='choose-a-long-password' \
  localhost/registry-ui:latest -runtime podman -podman-socket /run/podman/podman.sock \
  -listen 127.0.0.1:18080 -data-dir "$HOME/.local/share/registry-ui"
```

Open <http://127.0.0.1:18080> and sign in as `admin` with the password you chose. Passwords are 12-72
characters and may not contain the username. Without `REGISTRY_UI_ADMIN_PASSWORD`, a random password is generated and
printed **once** in `podman logs registry-ui`; the account must change it at first sign-in. The variable only matters
the first time (while there are no accounts): after that the admin account lives in the database.

Why each flag matters (do not drop them):

* `--network host`: so Stowage reaches tenant registries on `127.0.0.1:<port>`.
* `--userns keep-id --user`: so it runs as *your* uid, the only user allowed on your rootless podman socket.
* `--security-opt label=disable`: SELinux otherwise blocks a container from using the socket (harmless where SELinux is off).
* The data directory is mounted at the **same path** inside and out, because tenant registries bind-mount their config
  files from it by *host* path.

Start on boot: use the Quadlet in `deploy/podman/registry-ui.container` (its header lists the install steps; the admin
password goes in a `podman secret`). Run `loginctl enable-linger "$USER"` so it keeps running when you log out.

To reach it from other machines, change `-listen` to `0.0.0.0:18080` (or a specific address), open the firewall port
(`sudo firewall-cmd --add-port=18080/tcp --permanent && sudo firewall-cmd --reload`), and **put TLS in front of it**
(a reverse proxy that sends `X-Forwarded-Proto: https`, with `-trust-proxy`). The sign-in cookie is only marked secure over HTTPS. Tenant registries are
published on their own host ports (5100 and up), so open those too if clients on other machines push and pull.

### Option B: build and run the binary on the host

Needs Go-in-a-container (done for you by `make`) and **Node.js 22+ with npm** on the host for the UI build.

```sh
git clone git@github.com:rebontadeb/stowage-image-registry.git && cd stowage-image-registry
systemctl --user enable --now podman.socket
make build            # builds the UI, then bin/server (Go runs in registry.access.redhat.com/hi/go)
REGISTRY_UI_ADMIN_PASSWORD='choose-a-long-password' bin/server -listen 127.0.0.1:8080
```

`make test` runs the Go tests and `make vet` the checks. Go caches live in `~/.cache/registry-ui-go` (about 2 GB),
outside the project on purpose.

### First use, in five minutes

1. Sign in as `admin`. **Registries** then **New registry**: a name, a tenant name, and the first registry user.
2. The **Overview** tab shows the address (for example `127.0.0.1:5100`) and the `podman login` / `tag` / `push` commands.
3. Push an image: `podman login --tls-verify=false 127.0.0.1:5100`, then `podman push --tls-verify=false ...`
   (the `--tls-verify=false` is only needed until you enable HTTPS on the **TLS** tab).
4. **Images** shows it. **Scan image** runs the vulnerability scan; **Fix** and **Rebase** (see below) improve it.

### Images that are pulled on first use

Stowage downloads these itself the first time a feature needs them (it does not rely on you having pulled them), so the
first registry, scan or fix on a new machine is slower. All are public:

| Feature | Image |
|---|---|
| Tenant registry | `registry.access.redhat.com/hi/distribution:latest` |
| Go build (`make`) | `registry.access.redhat.com/hi/go:latest` |
| Container build | `registry.access.redhat.com/hi/nodejs:latest`, `hi/go`, `hi/static` |
| Vulnerability scan (also downloads its database on the first scan) | `registry.access.redhat.com/hi/grype:latest` |
| SBOM | `registry.access.redhat.com/hi/syft:latest` |
| Signatures | `registry.access.redhat.com/hi/cosign:latest` |
| Red Hat OVAL check | `registry.access.redhat.com/hi/openscap:latest` |
| Fix: RHEL/UBI and Debian/Ubuntu | `registry.access.redhat.com/ubi9/ubi-minimal:latest` (and `ubi<N>` for the image's RHEL release) |
| Fix: Alpine | `docker.io/library/alpine:<release>` |

Each can be changed with a `-tool-*-image` flag (below), for example to point at an internal mirror. To warm the
cache on a machine that will go offline, `podman pull` the ones you use.

## What is in the UI

* **Dashboard**: fleet status (running, stopped, HTTPS), storage used, and vulnerability totals across registries.
* **Registries**: one card per tenant. Open one for its tabs:
  * **Overview**: *Status* (address, transport, storage, image, created) next to *Contents* (repositories, image tags,
    scanned images, vulnerability counts, signatures, signing and trusted keys), then the *Connect* commands.
  * **Images**: repositories and tags; scan, sign, fix, rebase, copy the image name, add images.
  * **Registry users**, **TLS**, **Security** (signing and trusted keys), **Configuration**, **Access** (which Stowage
    accounts may see it), and **Delete registry** (admins; type the name to confirm).
* **Audit log**, **Accounts & access**, **Security tools** (admins).
* A **footer** on every page: product name, the build version, and links to the documentation and source. The version
  comes from `git describe` at build time (`make` and `make podman-image` pass it; a plain `go build` shows `dev`).
* Light and dark themes, a collapsible navigation, and a layout for phones (see [Navigation and mobile](#navigation-and-mobile)).

## Who can do what

| Role | Registries | Capabilities |
|---|---|---|
| **admin** | all | everything: create/delete registries, Stowage accounts, audit log, security tools, signing keys |
| **operator** | those in scope | start/stop, add/delete/scan/sign/**fix**/**rebase** images, run GC, registry users, TLS, configuration |
| **viewer** | those in scope | read-only: status, contents, scan results, images, registry users |

*Scope* is per account: every registry, or an explicit list. Registries outside an account's scope
look nonexistent (404, never 403). Deleting a registry revokes all access to it, so a new registry
with the same name starts clean. Role and scope changes apply on the next request, and disabling an
account ends its sessions immediately.

Stowage accounts are separate from **registry users** (the `podman login` credentials of a tenant).

## Sign-in

* **Local accounts**: bcrypt, sliding 8 h idle timeout, 24 h absolute cap, lock-out after 5 failures
  (per username) or 30 (per address), "change password at first sign-in", changing a password signs out other devices.
* **OpenID Connect** (Keycloak, Entra ID, Okta, OpenShift OAuth, ...): authorization-code flow with
  PKCE, `state` and `nonce`; the ID token is verified (signature, issuer, audience, expiry).
  The role is taken from the groups claim at **every** sign-in; registry scope is assigned by an admin.
  Users in no mapped group are refused.

```sh
REGISTRY_UI_OIDC_CLIENT_SECRET=... bin/server \
  -oidc-issuer https://sso.example.com/realms/corp -oidc-client-id stowage \
  -oidc-redirect-url https://registry-ui.example.com/api/auth/oidc/callback \
  -oidc-admin-groups registry-admins -oidc-operator-groups registry-operators -oidc-viewer-groups registry-viewers
```

Both can run together. `-disable-local-login` makes SSO the only way in (keep a local admin until SSO works).
Behind a TLS-terminating proxy, send `X-Forwarded-Proto: https` so cookies are marked `Secure`, and pass
`-trust-proxy` so the audit log and lock-out see real client addresses.

## Adding images from the UI

On a registry's **Images** tab, *Add image* (operators and admins) puts an image into the tenant's registry without a
command line, in the background with live progress (it keeps running if you close the dialog):

* **From a registry**: type any reference (`docker.io/library/alpine:3.19`, `quay.io/org/app:v1`,
  `registry.access.redhat.com/ubi9/ubi-micro:latest`). Private sources take a username and password or token, used for
  that one copy and never stored, logged or audited. Multi-architecture images are copied for this server's platform
  unless *Copy every architecture* is ticked.
* **Upload a file**: a docker-archive made with `podman save -o app.tar IMAGE` (or `docker save`), `.tar` or `.tar.gz`,
  one image per file. OCI-format archives are not supported.

The destination repository and tag are suggested from the source or file name. An existing tag is never replaced
unless *Replace the tag* is ticked, and the same destination cannot be written by two transfers at once. *Scan when added*
queues the vulnerability, SBOM and signature checks. Every transfer is audited (who, source, destination, digest, outcome).

Limits and safety: images above `-import-max-gib` (default 8) are refused before anything is pushed; at most two
transfers run at once; uploads are staged under the data directory and removed afterwards. The server connecting to the
source is guarded like the content import: loopback and link-local addresses (including cloud metadata endpoints) are
refused, so a user cannot use Stowage to reach services on the host or copy from another tenant's registry on the same
machine. Private-network sources are allowed. Sources given as a literal private IP may be reached over plain HTTP, as the
registry client library does by default; use a hostname with TLS for anything sensitive.

## Repositories and images

The **Images** tab lists a registry's repositories (name, tag count, worst vulnerability counts); open one for its tags.
Each tag row shows its vulnerability and signature status and these buttons, left to right:

| Button | Who | What it does |
|---|---|---|
| **Copy** | everyone | copies the full image name with the tag (`host:port/repo:tag`) |
| **Details** | everyone, with security on | scan results, SBOM, signature, compliance for that image |
| **Scan image** | operator | runs the vulnerability, SBOM and signature checks again |
| **Sign image** | operator, once a signing key exists | signs the exact image with the registry's key |
| **Fix** | operator, after a scan with findings | patches OS packages into a new `-fixed` tag (see below) |
| **Rebase** | operator | moves the image onto a newer base as a new `-rebased` tag (see below) |
| **Delete tag** | operator | removes the image, its signature and its stored scan results |

Operators can also **delete a whole repository** (the name must be typed to confirm) and free disk space from the
list's *More actions* menu.

Distribution has no repository-level delete and keeps listing an empty repository, so Stowage deletes every tag's manifest
(and signature index) and hides repositories that have no tags. Space is returned by garbage collection, which Stowage runs
with `--delete-untagged` so the per-architecture manifests left behind by a deleted multi-architecture image are reclaimed
too. Consequence: an image that only exists as an untagged manifest (pushed by digest, with no tag ever pointing at it) is
collected as well; give such images a tag.

## Image security: scans, SBOMs, signatures, Red Hat OVAL

Each registry's **Images** tab shows, per tag, its vulnerabilities (critical · high · medium · low) and
signature status, with a details dialog. Scans run on demand (operators click *Scan image*), are cached per
image **digest**, and are removed with the image. The dashboard and registry list roll the numbers up.

| Check | Tool image | What you get |
|---|---|---|
| Vulnerabilities | `hi/grype` | CVE table: severity, CVSS, package, fixed-in version; filter and sort |
| SBOM | `hi/syft` | package list (searchable) and CycloneDX / SPDX downloads |
| Signatures | `hi/cosign` | Signed / Unsigned / Not trusted / Signed-unverified, per trusted key |
| Signing | `hi/cosign` | operators sign an image with the registry's own key |
| Red Hat OVAL | `hi/openscap` | applicable Red Hat advisories for RHEL and UBI images, full OpenSCAP report |

How it is built to be safe:

* Every tool runs as a **short-lived container**: all capabilities dropped, no-new-privileges, 4 GiB / 1024-pid limits,
  a timeout, and removal afterwards. Registry credentials reach it in **environment variables, never arguments**.
* **Signing keys** are generated by Stowage (ECDSA P-256, cosign format). The private key and its random
  passphrase are encrypted at rest with AES-256-GCM under a master key from `REGISTRY_UI_MASTER_KEY` (base64, 32 bytes)
  or, if unset, a `master.key` file (mode 0600) created next to the database. Back that key up with the database.
  Signing is offline (no transparency log). Trust is explicit: an image counts as signed only if one of the
  registry's *trusted public keys* verifies it. Creating or deleting a signing key is admin-only.
* **Red Hat OVAL** needs content (administration -> *Security tools*: import Red Hat's feed over HTTPS or upload a
  file). The image's filesystem is unpacked into a scratch directory with `os.Root` confinement (no path traversal, no
  symlink escape, size and file-count caps), mounted read-only, and evaluated with `OSCAP_PROBE_ROOT`. The rpm probe
  needs `CAP_SYS_CHROOT`, which rootless podman grants safely (container root is still you) but restricted Kubernetes /
  OpenShift policies do not, so **the OVAL check is podman-only**. The other four work on both.
* Vulnerability data comes from the grype database, downloaded on the first scan into a cache volume (needs internet
  access, or a mirror). Results show the database build date; run the scan again to pick up newer data.
* Signature tags that cosign adds next to an image are hidden in the tag list and deleted together with the image.

**Fix.** After a vulnerability scan, an operator can press **Fix** on a tag. Stowage unpacks the image, upgrades its
operating-system packages inside the unpacked copy, packs what changed into one new layer, and pushes the result as
`<tag>-fixed`. The original is never touched, and the new image is scanned when it is ready so you can compare the two.
If the scan names packages with a fixed version only those are upgraded; otherwise every package that has an update is.

| Image family | Package manager used | Helper image |
|---|---|---|
| RHEL, UBI | `microdnf --installroot` | `ubi<major>/ubi-minimal` |
| Alpine | `apk --root`, with the image's own repositories | `alpine:<release>` |
| Debian, Ubuntu | the image's own `apt`, in a chroot of the unpacked image | `ubi9/ubi-minimal` (shell and `chroot` only) |

Limits, stated plainly:

* Only **OS packages** are patched, from the repositories the image was built for. Application dependencies (npm, pip,
  Go modules), a language runtime built or copied into the image (the Python of a `python:3.x` image, nginx itself),
  and distroless images are not touched. For those, use **Rebase** or rebuild from your Dockerfile.
* Many advisories are marked "not fixed" by scanners, and an end-of-life distribution release gets no new packages.
  Compare the new scan with the old one: the counts may drop a lot (a Debian Python image went from 503 to 214
  findings) or not at all (Alpine 3.14).
* The machine needs internet access to the distribution's package repositories.
* **Podman only**: the unpacked image is bind-mounted into a helper container, like the OVAL check.
* The result keeps the original's image format (OCI or Docker) and every layer is of the matching type, so strict
  registries such as quay.io accept it. Images fixed or rebased by Stowage before 2026-10-09 may mix the two and be
  refused when pushed on (`unsupported MIME type for compression`): run Fix or Rebase on the original again.
* File owners in the new layer are flattened to root (rootless users cannot read other owners); modes, including
  setuid bits, are kept. Unchanged files are not repeated in the layer.

**Rebase.** The real fix for findings that have no patch (an end-of-life base such as Alpine 3.14 or OpenSSL 1.1) is a
newer base. **Rebase** takes the base the image was built on and a newer one, and pushes `<tag>-rebased` whose own
layers sit on the new base. The original is untouched, the image's user, command and environment are kept, and the new
image is scanned.

In the dialog, give the new base and **either** the old base (the `FROM` line of the Dockerfile; **Check** tells you
whether the image really starts with its layers) **or** the number of leading layers that belong to the base. Use the
layer count when the old base's tag has been rebuilt since the image was made, which is common: layers are compared by
content, so a moved tag no longer matches. The dialog's *How this image was built* list shows which layers are which.

* Rebase copies your layers as they are, it does not rebuild anything: test that the new image still starts.
  Variables set by the old base (for example `NGINX_VERSION`) keep their old values.
* It is **not for language-runtime images**: layers from `pip install` or `npm install` are tied to the old runtime
  version (`python3.9/site-packages`) and the container will not start on a newer one. Rebuild those from their Dockerfile.
* It suits images that add files or configuration to an OS or server base, such as nginx.
* Needs access to the base images' registries. It uses only the registry API, so it is not tied to podman, but it has
  not been run on Kubernetes.

Flags: `-import-max-gib` sets the Add image size limit, `-security=false` turns the checks off, `-scan-workers`, `-tool-{syft,grype,cosign,openscap}-image` to pin images, `-tool-fix-debian-image` (shell + chroot helper, default ubi-minimal), `-tool-fix-alpine-image` (default `docker.io/library/alpine:%s`) and `-tool-fix-image` (default `registry.access.redhat.com/ubi%s/ubi-minimal:latest`, `%s` = RHEL major) for Fix.

## Audit log

Every state-changing call is recorded (also denied ones): who, role, action, target, outcome, client IP and
safe details (never passwords, keys or env values, only env variable *names*). Filter in the UI (actor, action, target, outcome, time range), page through it
(10, 25, 50 or 100 rows per page; the wide table scrolls sideways), or export CSV (formula-injection safe). Retention: `-audit-retention-days` (default 365).

## Kubernetes / OpenShift

```sh
podman build -f deploy/Containerfile -t <registry>/registry-ui:latest . && podman push <registry>/registry-ui:latest
# edit the image in deploy/k8s/registry-ui.yaml, create the registry-ui-auth secret (see the file), then:
kubectl apply -f deploy/k8s/registry-ui.yaml
```

Each tenant registry becomes a Deployment, Service, PVC and Secret; `-k8s-expose=route|ingress` adds
`<name>.<domain>`. Storage usage numbers need the optional `nodes/proxy` ClusterRole in the manifest.

## Configuration reference

Flags go after the image name (container) or after `bin/server`. The first-run admin password is the only setting
read from the environment: `REGISTRY_UI_ADMIN_PASSWORD`.

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `127.0.0.1:8080` | address of the UI and API |
| `-data-dir` | `~/.local/share/registry-ui` | state: database, secrets key, tenant config, scratch |
| `-runtime` | `podman` | `podman`, `kubernetes`, or `fake` (UI development, no containers) |
| `-podman-socket` | the user's podman socket | podman API socket |
| `-port-min`, `-port-max` | `5100`, `5999` | host ports handed to tenant registries |
| `-trust-proxy` | off | take client addresses and HTTPS from `X-Forwarded-*` (only behind a proxy you control) |
| `-disable-local-login` | off | allow single sign-on only |
| `-audit-retention-days` | `365` | delete audit entries older than this |
| `-import-max-gib` | `8` | largest image Add image, Fix and Rebase accept |
| `-security` | on | scans, SBOMs, signing, compliance, Fix and Rebase |
| `-scan-workers` | `2` | concurrent scan jobs |
| `-tool-*-image` | see "Images that are pulled on first use" | helper images (`syft`, `grype`, `cosign`, `openscap`, `fix`, `fix-alpine`, `fix-debian`) |
| `-oidc-*` | off | single sign-on, see [Sign-in](#sign-in) |
| `-kubeconfig`, `-k8s-*` | | Kubernetes runtime, see [Kubernetes / OpenShift](#kubernetes--openshift) |

Run `bin/server -h` (or `podman run --rm localhost/registry-ui:latest -h`) for the full list.

## Operating it: data, backup, upgrade, uninstall

**Where the state is.** Everything Stowage owns is in the data directory (`~/.local/share/registry-ui` in the recipes):
`registry-ui.db` (accounts, tenants, scan results, audit log), `master.key` (encrypts signing keys; **lose it and the
signing keys are unreadable**), per-registry config and certificates, and `scratch/` (temporary). Tenant images live
in podman volumes named `reg-<name>-data`.

**Back up** (stop Stowage first so the database is consistent; tenant registries can keep running):

```sh
podman stop registry-ui
tar -C ~/.local/share -czf stowage-state-$(date +%F).tgz registry-ui
for v in $(podman volume ls -q --filter name=reg-); do podman volume export "$v" -o "$v.tar"; done   # tenant images
podman start registry-ui
```

**Move to another machine.** Install as above, stop Stowage on both, restore the state directory to the **same path**
on the new machine (the path appears inside tenant config), `podman volume import` the volumes, start Stowage. Tenant
registries are recreated from the database. Host ports must still be free.

**Upgrade.**

```sh
cd stowage-image-registry && git pull
make podman-image
podman rm -f registry-ui        # tenant registries keep running, they are separate containers
# run the same `podman run ...` command as before
```

The database upgrades itself on start. Pin a known-good image with `podman tag localhost/registry-ui:latest
localhost/registry-ui:<date>` before upgrading so you can roll back.

**Uninstall.**

```sh
podman rm -f registry-ui
podman rm -f $(podman ps -aq --filter name=reg-)            # tenant registries (their data stays in the volumes)
podman volume rm $(podman volume ls -q --filter name=reg-)  # ONLY if you want the images gone for good
rm -rf ~/.local/share/registry-ui
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `make podman-image` fails pulling `registry.access.redhat.com/hi/...` | No route to the registry, or a corporate proxy. Test `podman pull registry.access.redhat.com/hi/go:latest`; mirror the images and adjust the `FROM` lines in `deploy/Containerfile`. |
| The very first "New registry" takes a while | Stowage downloads the `distribution` image (about 85 MB) on first use. Later registries are instant. Pull it ahead with `podman pull registry.access.redhat.com/hi/distribution:latest`. |
| "container image unavailable: pulling ... failed" | The machine cannot download that image: check internet or proxy access to the registry named in the message, or `podman login` for a private one, then try again. |
| UI loads but "Create registry" fails with a connection error | The podman socket is not reachable: `systemctl --user enable --now podman.socket`, and check the `-v ...podman.sock` mount path. |
| `permission denied` on the podman socket from the container | Missing `--userns keep-id --user "$(id -u):$(id -g)"` or `--security-opt label=disable` (SELinux). |
| Registry shows "starting" forever, or its config file is missing | The data directory is not mounted at the same path inside and outside the container. |
| Port already in use | Another service holds the UI port or a tenant port: change `-listen` or `-port-min/-port-max`. |
| First scan is slow or fails offline | The vulnerability database is downloaded on the first scan (needs internet or a mirror). |
| Fix fails with an apt or network error | Fix downloads packages from the image's own repositories; the machine needs internet access to them. |
| Fix says nothing to fix, or counts do not drop | Scanners mark many advisories "not fixed". See the Fix section; the real remedy is a newer base image, rebuilt from your Dockerfile. |
| A rebased image will not start | Rebase is not for language-runtime images (`pip install`, `npm install`). Rebuild from the Dockerfile instead. |
| Sign-in loops over HTTPS behind a proxy | Add `-trust-proxy` and make the proxy send `X-Forwarded-Proto: https`. |
| Forgot the admin password | Another admin can reset it under **Accounts & access**. If no admin can sign in: stop Stowage, back up the data directory, run `sqlite3 registry-ui.db 'DELETE FROM accounts;'` (this also removes every other account and its access settings, but not tenants or images), then start Stowage with `REGISTRY_UI_ADMIN_PASSWORD` set. The first admin is only created while there are no accounts. `REGISTRY_UI_ADMIN_USER` changes the user name (default `admin`). |

## Known limits

* Single Stowage replica (SQLite on one volume).
* Changing users, TLS or configuration restarts that tenant's registry for a few seconds.
* TLS keys and the internal admin password are stored unencrypted in Stowage's database; protect its volume.
* Podman gives each registry a host port; hostname routing needs your own reverse proxy.
* Kubernetes support is tested with fakes and a real image build, not yet against a live cluster. Tool jobs there
  merge stdout and stderr and use scratch space for the vulnerability database (re-downloaded per scan).
* Signing keys can be replaced but not rotated in place: delete the key, create a new one, and keep the old public
  key trusted for as long as old signatures matter.

## Naming

The product is **Stowage**. Technical identifiers keep their original names so existing installs and
scripts keep working: the binary, image and Kubernetes namespace are `registry-ui`, the session cookie is
`rui_session`, and the API and database call a tenant's registry owner `customer` (the UI says "Tenant").

## Fonts

The UI uses **Inter** for text and **JetBrains Mono** for code, digests and commands, both self-hosted
(the content security policy blocks font CDNs, and installs may be offline). Only the Latin and Latin Extended
subsets are bundled (about 190 KB, loaded on demand). Both are SIL OFL 1.1; the licence text is served at
`/licenses/fonts.txt`. To support another script, copy its subset file and `@font-face` block from the
`@fontsource-variable/inter` package into `web/src/fonts/`.

## Navigation and mobile

* **Desktop:** the left navigation collapses to an icon rail with the *Collapse navigation* button at its bottom
  (the choice is remembered in the browser). Links keep their names for screen readers and show tooltips when collapsed.
* **Phones and tablets (900 px and below):** navigation is a drawer opened from the menu button. It closes on Escape,
  on a tap outside it, or when you pick a destination; while it is open the page behind it cannot be focused or scrolled,
  and focus returns to the menu button afterwards. Theme and sign-out live in the drawer.
* **Small screens (600 px and below):** tables turn into stacked cards (with a *Sort by* selector, since the header row is
  hidden), dialogs become bottom sheets, form fields are 16 px so iOS does not zoom, and touch devices get larger targets.

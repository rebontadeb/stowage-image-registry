// Package kubernetes implements runtime.Driver on any Kubernetes distribution, with optional
// OpenShift Route or Ingress exposure.
//
// Per registry it manages: Secret (mounted files), PVC (data), Deployment (1 or 0 replicas),
// Service, and optionally a Route or Ingress. Start/Stop scale the Deployment; GC runs a Job that
// reuses the Deployment's pod spec so it sees identical volumes and config.
package kubernetes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

const (
	registryPort = 5000
	portName     = "registry"
	dataTarget   = "/var/lib/registry"
	configPath   = "/etc/distribution/config.yml"
	tlsEnvKey    = "REGISTRY_HTTP_TLS_CERTIFICATE"

	labelManaged  = "app.kubernetes.io/managed-by"
	labelInstance = "registry-ui/instance"
	managedBy     = "registry-ui"
)

// Expose selects how registries are reachable from outside the cluster.
type Expose string

const (
	ExposeNone    Expose = ""        // ClusterIP Service only
	ExposeRoute   Expose = "route"   // OpenShift Route
	ExposeIngress Expose = "ingress" // networking.k8s.io Ingress
)

type Config struct {
	Namespace        string
	StorageClass     string // "" = cluster default
	Expose           Expose
	Domain           string // base domain; registry host is <name>.<Domain>
	IngressClass     string
	IngressTLSSecret string // optional TLS secret for Ingress hosts
	// FSGroup sets the pod fsGroup. Leave 0 on OpenShift (the restricted SCC assigns one).
	FSGroup int64
}

var routeGVR = schema.GroupVersionResource{Group: "route.openshift.io", Version: "v1", Resource: "routes"}

type Driver struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface // only needed for ExposeRoute
	cfg Config

	poll        time.Duration
	stopTimeout time.Duration
	gcTimeout   time.Duration
	// stats fetches the kubelet stats summary for a node (overridable for tests).
	stats func(ctx context.Context, node string) ([]byte, error)
}

func New(cs kubernetes.Interface, dyn dynamic.Interface, cfg Config) (*Driver, error) {
	if cfg.Namespace == "" {
		return nil, errors.New("kubernetes: namespace required")
	}
	if cfg.Expose != ExposeNone && cfg.Domain == "" {
		return nil, errors.New("kubernetes: a base domain is required when exposing registries")
	}
	if cfg.Expose == ExposeRoute && dyn == nil {
		return nil, errors.New("kubernetes: route exposure needs a dynamic client")
	}
	d := &Driver{cs: cs, dyn: dyn, cfg: cfg, poll: 2 * time.Second, stopTimeout: 2 * time.Minute, gcTimeout: 10 * time.Minute}
	d.stats = d.kubeletStats
	return d, nil
}

func res(name string) string        { return "reg-" + name }
func secretName(name string) string { return res(name) + "-files" }
func pvcName(name string) string    { return res(name) + "-data" }
func gcName(name string) string     { return res(name) + "-gc" }

func (d *Driver) labels(name string) map[string]string {
	return map[string]string{labelManaged: managedBy, labelInstance: name}
}

func (d *Driver) selector(name string) string {
	return fmt.Sprintf("%s=%s", labelInstance, name)
}

func (d *Driver) host(name string) string { return name + "." + d.cfg.Domain }

func hasTLS(env map[string]string) bool { return env[tlsEnvKey] != "" }

// ---- Create ----

func (d *Driver) Create(ctx context.Context, s runtime.Spec) error {
	if s.Image == "" {
		s.Image = runtime.DefaultImage
	}
	qty, err := resource.ParseQuantity(orDefault(s.StorageSize, "10Gi"))
	if err != nil {
		return fmt.Errorf("storage size %q: %w", s.StorageSize, err)
	}
	ns := d.cfg.Namespace
	lbl := d.labels(s.Name)

	if len(s.Files) > 0 {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName(s.Name), Namespace: ns, Labels: lbl},
			Data:       map[string][]byte{},
		}
		for i, f := range s.Files {
			sec.Data[fileKey(i)] = f.Content
		}
		if _, err := d.cs.CoreV1().Secrets(ns).Create(ctx, sec, metav1.CreateOptions{}); apierrors.IsAlreadyExists(err) {
			_, err = d.cs.CoreV1().Secrets(ns).Update(ctx, sec, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: pvcName(s.Name), Namespace: ns, Labels: lbl},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: qty}},
		},
	}
	if d.cfg.StorageClass != "" {
		sc := d.cfg.StorageClass
		pvc.Spec.StorageClassName = &sc
	}
	// An existing claim holds the tenant's data: keep it untouched.
	if _, err := d.cs.CoreV1().PersistentVolumeClaims(ns).Create(ctx, pvc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	dep := d.deployment(s)
	if _, err := d.cs.AppsV1().Deployments(ns).Create(ctx, dep, metav1.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		if _, err = d.cs.AppsV1().Deployments(ns).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: res(s.Name), Namespace: ns, Labels: lbl},
		Spec: corev1.ServiceSpec{
			Selector: lbl,
			Ports:    []corev1.ServicePort{{Name: portName, Port: registryPort, TargetPort: intstr.FromString(portName)}},
		},
	}
	if _, err := d.cs.CoreV1().Services(ns).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return d.expose(ctx, s.Name, hasTLS(s.Env))
}

func fileKey(i int) string { return fmt.Sprintf("f%d", i) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func ptr[T any](v T) *T { return &v }

func (d *Driver) deployment(s runtime.Spec) *appsv1.Deployment {
	lbl := d.labels(s.Name)

	var env []corev1.EnvVar
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable pod template: no spurious rollouts
	for _, k := range keys {
		env = append(env, corev1.EnvVar{Name: k, Value: s.Env[k]})
	}

	mounts := []corev1.VolumeMount{{Name: "data", MountPath: dataTarget}}
	volumes := []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: pvcName(s.Name)},
	}}}
	if len(s.Files) > 0 {
		var items []corev1.KeyToPath
		for i, f := range s.Files {
			items = append(items, corev1.KeyToPath{Key: fileKey(i), Path: fileKey(i)})
			mounts = append(mounts, corev1.VolumeMount{Name: "files", MountPath: f.Path, SubPath: fileKey(i), ReadOnly: true})
		}
		volumes = append(volumes, corev1.Volume{Name: "files", VolumeSource: corev1.VolumeSource{
			// 0444: the image runs as a non-root uid that is not the volume owner.
			Secret: &corev1.SecretVolumeSource{SecretName: secretName(s.Name), DefaultMode: ptr(int32(0o444)), Items: items},
		}})
	}

	probe := func() *corev1.Probe {
		// tcpSocket: /v2/ answers 401 (auth is always on), which an HTTP probe would count as failure.
		return &corev1.Probe{
			ProbeHandler:  corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromString(portName)}},
			PeriodSeconds: 10,
		}
	}
	live := probe()
	live.InitialDelaySeconds = 15

	podSec := &corev1.PodSecurityContext{
		RunAsNonRoot:   ptr(true),
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	if d.cfg.FSGroup != 0 {
		podSec.FSGroup = ptr(d.cfg.FSGroup)
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: res(s.Name), Namespace: d.cfg.Namespace, Labels: lbl},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(int32(0)),
			Selector: &metav1.LabelSelector{MatchLabels: lbl},
			// RWO volume: the old pod must release it before the new one starts.
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: lbl},
				Spec: corev1.PodSpec{
					SecurityContext: podSec,
					Containers: []corev1.Container{{
						Name:           "registry",
						Image:          s.Image,
						Env:            env,
						Ports:          []corev1.ContainerPort{{Name: portName, ContainerPort: registryPort}},
						VolumeMounts:   mounts,
						ReadinessProbe: probe(),
						LivenessProbe:  live,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes: volumes,
				},
			},
		},
	}
}

// expose creates the external entry point (Route or Ingress) when configured.
func (d *Driver) expose(ctx context.Context, name string, tls bool) error {
	ns, host := d.cfg.Namespace, d.host(name)
	switch d.cfg.Expose {
	case ExposeRoute:
		spec := map[string]any{
			"host": host,
			"to":   map[string]any{"kind": "Service", "name": res(name)},
			"port": map[string]any{"targetPort": portName},
		}
		if tls {
			// The registry terminates TLS itself, so the router must pass the stream through.
			spec["tls"] = map[string]any{"termination": "passthrough", "insecureEdgeTerminationPolicy": "Redirect"}
		}
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "route.openshift.io/v1", "kind": "Route",
			"metadata": map[string]any{
				"name": res(name), "namespace": ns,
				"labels":      toAny(d.labels(name)),
				"annotations": map[string]any{"haproxy.router.openshift.io/timeout": "10m"}, // large layer pushes
			},
			"spec": spec,
		}}
		_, err := d.dyn.Resource(routeGVR).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	case ExposeIngress:
		pathType := netv1.PathTypePrefix
		ann := map[string]string{"nginx.ingress.kubernetes.io/proxy-body-size": "0"} // no size cap on layer uploads
		if tls {
			ann["nginx.ingress.kubernetes.io/backend-protocol"] = "HTTPS"
		}
		ing := &netv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: res(name), Namespace: ns, Labels: d.labels(name), Annotations: ann},
			Spec: netv1.IngressSpec{
				Rules: []netv1.IngressRule{{Host: host, IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{
					Paths: []netv1.HTTPIngressPath{{Path: "/", PathType: &pathType, Backend: netv1.IngressBackend{
						Service: &netv1.IngressServiceBackend{Name: res(name), Port: netv1.ServiceBackendPort{Name: portName}},
					}}},
				}}}},
			},
		}
		if d.cfg.IngressClass != "" {
			ing.Spec.IngressClassName = ptr(d.cfg.IngressClass)
		}
		if d.cfg.IngressTLSSecret != "" {
			ing.Spec.TLS = []netv1.IngressTLS{{Hosts: []string{host}, SecretName: d.cfg.IngressTLSSecret}}
		}
		_, err := d.cs.NetworkingV1().Ingresses(ns).Create(ctx, ing, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

func toAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- lifecycle ----

func (d *Driver) scale(ctx context.Context, name string, replicas int32) error {
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))
	_, err := d.cs.AppsV1().Deployments(d.cfg.Namespace).Patch(ctx, res(name), types.MergePatchType, patch, metav1.PatchOptions{})
	if apierrors.IsNotFound(err) {
		return runtime.ErrNotFound
	}
	return err
}

func (d *Driver) Start(ctx context.Context, name string) error { return d.scale(ctx, name, 1) }

// Stop scales to zero and waits until the pod is gone, so the RWO volume is free for a GC Job.
func (d *Driver) Stop(ctx context.Context, name string) error {
	if err := d.scale(ctx, name, 0); err != nil {
		return err
	}
	return d.waitNoPods(ctx, d.selector(name), d.stopTimeout)
}

func (d *Driver) waitNoPods(ctx context.Context, selector string, timeout time.Duration) error {
	return d.until(ctx, timeout, "pods to terminate", func() (bool, error) {
		pods, err := d.cs.CoreV1().Pods(d.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		return err == nil && len(pods.Items) == 0, err
	})
}

func (d *Driver) until(ctx context.Context, timeout time.Duration, what string, cond func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", what)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.poll):
		}
	}
}

func (d *Driver) Delete(ctx context.Context, name string, removeData bool) error {
	ns := d.cfg.Namespace
	bg := metav1.DeleteOptions{PropagationPolicy: ptr(metav1.DeletePropagationBackground)}
	ignore := func(err error) error {
		if err == nil || apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if d.cfg.Expose == ExposeRoute {
		if err := ignore(d.dyn.Resource(routeGVR).Namespace(ns).Delete(ctx, res(name), bg)); err != nil {
			return err
		}
	}
	if d.cfg.Expose == ExposeIngress {
		if err := ignore(d.cs.NetworkingV1().Ingresses(ns).Delete(ctx, res(name), bg)); err != nil {
			return err
		}
	}
	steps := []func() error{
		func() error { return d.cs.CoreV1().Services(ns).Delete(ctx, res(name), bg) },
		func() error { return d.cs.AppsV1().Deployments(ns).Delete(ctx, res(name), bg) },
		func() error { return d.cs.BatchV1().Jobs(ns).Delete(ctx, gcName(name), bg) },
		func() error { return d.cs.CoreV1().Secrets(ns).Delete(ctx, secretName(name), bg) },
	}
	for _, f := range steps {
		if err := ignore(f()); err != nil {
			return err
		}
	}
	// A recreate reuses the RWO claim, so the old pod must be gone first.
	if err := d.waitNoPods(ctx, d.selector(name), d.stopTimeout); err != nil {
		return err
	}
	if removeData {
		return ignore(d.cs.CoreV1().PersistentVolumeClaims(ns).Delete(ctx, pvcName(name), bg))
	}
	return nil
}

func (d *Driver) Status(ctx context.Context, name string) (runtime.Status, error) {
	dep, err := d.cs.AppsV1().Deployments(d.cfg.Namespace).Get(ctx, res(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return runtime.Status{State: runtime.StateMissing}, nil
	}
	if err != nil {
		return runtime.Status{}, err
	}
	st := runtime.Status{
		State:    runtime.StateStopped,
		Endpoint: fmt.Sprintf("%s.%s.svc:%d", res(name), d.cfg.Namespace, registryPort),
	}
	if d.cfg.Expose != ExposeNone {
		st.PublicHost = d.host(name)
	}
	if dep.Spec.Replicas != nil && *dep.Spec.Replicas > 0 {
		st.State = runtime.StateStarting
		if dep.Status.ReadyReplicas > 0 {
			st.State = runtime.StateRunning
		}
	}
	return st, nil
}

// ---- GC ----

func (d *Driver) RunGC(ctx context.Context, name string) (string, error) {
	ns := d.cfg.Namespace
	dep, err := d.cs.AppsV1().Deployments(ns).Get(ctx, res(name), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", runtime.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if dep.Spec.Replicas != nil && *dep.Spec.Replicas > 0 {
		return "", fmt.Errorf("stop instance %q before garbage collection", name)
	}
	if err := d.waitNoPods(ctx, d.selector(name), d.stopTimeout); err != nil {
		return "", err
	}

	// Same volumes, mounts and env as the registry, different command.
	pod := *dep.Spec.Template.Spec.DeepCopy()
	c := &pod.Containers[0]
	c.Args = []string{"garbage-collect", "--delete-untagged", configPath}
	c.Command, c.Ports, c.ReadinessProbe, c.LivenessProbe = nil, nil, nil, nil
	pod.RestartPolicy = corev1.RestartPolicyNever

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: gcName(name), Namespace: ns, Labels: d.labels(name)},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr(int32(0)),
			TTLSecondsAfterFinished: ptr(int32(300)), // safety net if we crash before cleanup
			Template: corev1.PodTemplateSpec{
				// A distinct label keeps the GC pod out of the registry Service's selector.
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{labelManaged: managedBy, "registry-ui/gc": name}},
				Spec:       pod,
			},
		},
	}
	bg := metav1.DeleteOptions{PropagationPolicy: ptr(metav1.DeletePropagationBackground)}
	_ = d.cs.BatchV1().Jobs(ns).Delete(ctx, job.Name, bg) // leftover from an earlier run
	if err := d.until(ctx, time.Minute, "old GC job removal", func() (bool, error) {
		_, err := d.cs.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		return apierrors.IsNotFound(err), nil
	}); err != nil {
		return "", err
	}
	if _, err := d.cs.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return "", err
	}
	defer d.cs.BatchV1().Jobs(ns).Delete(context.WithoutCancel(ctx), job.Name, bg)

	var failed bool
	if err := d.until(ctx, d.gcTimeout, "garbage collection", func() (bool, error) {
		j, err := d.cs.BatchV1().Jobs(ns).Get(ctx, job.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		failed = j.Status.Failed > 0
		return j.Status.Succeeded > 0 || failed, nil
	}); err != nil {
		return "", err
	}

	logs := d.jobLogs(ctx, job.Name)
	if failed {
		return logs, errors.New("garbage-collect job failed")
	}
	return logs, nil
}

func (d *Driver) jobLogs(ctx context.Context, job string) string {
	ns := d.cfg.Namespace
	pods, err := d.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + job})
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	b, err := d.cs.CoreV1().Pods(ns).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{}).DoRaw(ctx)
	if err != nil {
		return ""
	}
	return string(b)
}

// ---- usage ----

// UsedBytes reads per-volume usage from the kubelet stats of the node running the pod. That needs
// nodes/proxy access, and a running pod; otherwise it reports runtime.ErrUnsupported.
func (d *Driver) UsedBytes(ctx context.Context, name string) (int64, error) {
	pods, err := d.cs.CoreV1().Pods(d.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: d.selector(name)})
	if err != nil {
		return 0, err
	}
	var node string
	for _, p := range pods.Items {
		if p.Spec.NodeName != "" {
			node = p.Spec.NodeName
			break
		}
	}
	if node == "" {
		return 0, fmt.Errorf("%w: no running pod to measure", runtime.ErrUnsupported)
	}
	raw, err := d.stats(ctx, node)
	if err != nil {
		return 0, fmt.Errorf("%w: kubelet stats: %v", runtime.ErrUnsupported, err)
	}
	var sum struct {
		Pods []struct {
			Volume []struct {
				UsedBytes *int64 `json:"usedBytes"`
				PVCRef    *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"pvcRef"`
			} `json:"volume"`
		} `json:"pods"`
	}
	if err := json.Unmarshal(raw, &sum); err != nil {
		return 0, err
	}
	for _, p := range sum.Pods {
		for _, v := range p.Volume {
			if v.PVCRef != nil && v.PVCRef.Name == pvcName(name) && v.PVCRef.Namespace == d.cfg.Namespace && v.UsedBytes != nil {
				return *v.UsedBytes, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: volume not in kubelet stats", runtime.ErrUnsupported)
}

func (d *Driver) kubeletStats(ctx context.Context, node string) ([]byte, error) {
	rc := d.cs.CoreV1().RESTClient()
	return rc.Get().AbsPath("/api/v1/nodes/" + node + "/proxy/stats/summary").DoRaw(ctx)
}

// RunTool runs a tool as a Job and returns its log. Pod logs merge stdout and stderr, so callers
// should run tools in quiet/JSON mode. Host mounts, extra capabilities and root are not
// available (they conflict with restricted pod security), so such specs report ErrUnsupported.
// Cache volumes are scratch space: they live as long as the pod.
func (d *Driver) RunTool(ctx context.Context, t runtime.ToolSpec) (runtime.ToolResult, error) {
	if len(t.Mounts) > 0 || len(t.Caps) > 0 || t.Root {
		return runtime.ToolResult{}, fmt.Errorf("%w: host mounts, capabilities and root are not available on Kubernetes", runtime.ErrUnsupported)
	}
	if t.Timeout <= 0 {
		t.Timeout = 10 * time.Minute
	}
	ns := d.cfg.Namespace
	idb := make([]byte, 5)
	_, _ = rand.Read(idb)
	name := "regui-tool-" + hex.EncodeToString(idb)

	var env []corev1.EnvVar
	keys := make([]string, 0, len(t.Env))
	for k := range t.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Secrets travel as env of a short-lived Job; the Job (and its pod) is deleted afterwards.
	for _, k := range keys {
		env = append(env, corev1.EnvVar{Name: k, Value: t.Env[k]})
	}
	if _, ok := t.Env["HOME"]; !ok {
		env = append(env, corev1.EnvVar{Name: "HOME", Value: "/tmp"}) // read-only rootfs: tools need a writable home
	}
	var vols []corev1.Volume
	var mounts []corev1.VolumeMount
	for i, v := range t.Volumes {
		vn := fmt.Sprintf("cache%d", i)
		vols = append(vols, corev1.Volume{Name: vn, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		mounts = append(mounts, corev1.VolumeMount{Name: vn, MountPath: v.Dest})
	}
	vols = append(vols, corev1.Volume{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	mounts = append(mounts, corev1.VolumeMount{Name: "tmp", MountPath: "/tmp"})

	deadline := int64(t.Timeout.Seconds())
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{labelManaged: managedBy, "registry-ui/tool": "true"}},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr(int32(0)), ActiveDeadlineSeconds: &deadline, TTLSecondsAfterFinished: ptr(int32(300)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{labelManaged: managedBy, "registry-ui/tool": "true"}},
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
					Containers: []corev1.Container{{
						Name: "tool", Image: t.Image, Args: t.Args, Env: env, VolumeMounts: mounts,
						SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false), ReadOnlyRootFilesystem: ptr(true),
							Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
					}},
					Volumes: vols,
				},
			},
		},
	}
	bg := metav1.DeleteOptions{PropagationPolicy: ptr(metav1.DeletePropagationBackground)}
	if _, err := d.cs.BatchV1().Jobs(ns).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return runtime.ToolResult{}, err
	}
	defer d.cs.BatchV1().Jobs(ns).Delete(context.WithoutCancel(ctx), name, bg)

	var failed bool
	if err := d.until(ctx, t.Timeout+30*time.Second, "tool "+name, func() (bool, error) {
		j, err := d.cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		failed = j.Status.Failed > 0
		return j.Status.Succeeded > 0 || failed, nil
	}); err != nil {
		return runtime.ToolResult{}, err
	}
	res := runtime.ToolResult{Stdout: []byte(d.jobLogs(ctx, name))}
	if failed {
		res.ExitCode = 1
	}
	return res, nil
}

var _ runtime.Driver = (*Driver)(nil)

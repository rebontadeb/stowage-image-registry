package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/rdeb/local-image-registry/internal/runtime"
)

const ns = "regs"

func newDriver(t *testing.T, cfg Config) (*Driver, *fake.Clientset) {
	t.Helper()
	cfg.Namespace = ns
	cs := fake.NewClientset()
	var dyn *dynfake.FakeDynamicClient
	if cfg.Expose == ExposeRoute {
		dyn = dynfake.NewSimpleDynamicClientWithCustomListKinds(k8sruntime.NewScheme(),
			map[schema.GroupVersionResource]string{routeGVR: "RouteList"})
	}
	var d *Driver
	var err error
	if dyn != nil {
		d, err = New(cs, dyn, cfg)
	} else {
		d, err = New(cs, nil, cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	d.poll = time.Millisecond
	d.stopTimeout = time.Second
	d.gcTimeout = time.Second
	return d, cs
}

func spec() runtime.Spec {
	return runtime.Spec{
		Name: "acme", StorageSize: "5Gi",
		Env:   map[string]string{"REGISTRY_AUTH": "htpasswd", "A_FIRST": "1"},
		Files: []runtime.File{{Path: "/auth/htpasswd", Content: []byte("u:h\n")}, {Path: "/etc/distribution/config.yml", Content: []byte("version: 0.1\n")}},
	}
}

func TestCreateBuildsExpectedObjects(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{StorageClass: "fast"})
	if err := d.Create(ctx, spec()); err != nil {
		t.Fatal(err)
	}

	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, "reg-acme-files", metav1.GetOptions{})
	if err != nil || string(sec.Data["f0"]) != "u:h\n" || len(sec.Data) != 2 {
		t.Fatalf("secret: %+v %v", sec, err)
	}
	pvc, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, "reg-acme-data", metav1.GetOptions{})
	if err != nil || pvc.Spec.Resources.Requests.Storage().String() != "5Gi" || *pvc.Spec.StorageClassName != "fast" {
		t.Fatalf("pvc: %+v %v", pvc, err)
	}
	dep, err := cs.AppsV1().Deployments(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *dep.Spec.Replicas != 0 {
		t.Fatal("Create must not start the registry")
	}
	c := dep.Spec.Template.Spec.Containers[0]
	if c.Image != runtime.DefaultImage {
		t.Fatalf("image: %s", c.Image)
	}
	if c.Env[0].Name != "A_FIRST" || c.Env[1].Name != "REGISTRY_AUTH" {
		t.Fatalf("env not sorted: %v", c.Env)
	}
	var cfgMount *corev1.VolumeMount
	for i, m := range c.VolumeMounts {
		if m.MountPath == "/etc/distribution/config.yml" {
			cfgMount = &c.VolumeMounts[i]
		}
	}
	if cfgMount == nil || cfgMount.SubPath != "f1" || !cfgMount.ReadOnly {
		t.Fatalf("config mount: %+v", cfgMount)
	}
	if c.ReadinessProbe.TCPSocket == nil || c.ReadinessProbe.HTTPGet != nil {
		t.Fatal("probe must be tcp: /v2/ answers 401")
	}
	if !*dep.Spec.Template.Spec.SecurityContext.RunAsNonRoot || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("pod must be restricted-SCC compatible")
	}
	if dep.Spec.Template.Spec.SecurityContext.FSGroup != nil {
		t.Fatal("fsGroup must be unset by default (OpenShift assigns it)")
	}
	svc, err := cs.CoreV1().Services(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
	if err != nil || svc.Spec.Ports[0].Port != 5000 || svc.Spec.Selector[labelInstance] != "acme" {
		t.Fatalf("service: %+v %v", svc, err)
	}
}

func TestBadStorageSize(t *testing.T) {
	d, _ := newDriver(t, Config{})
	s := spec()
	s.StorageSize = "lots"
	if err := d.Create(context.Background(), s); err == nil {
		t.Fatal("want error")
	}
}

func TestStatusStartStop(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	if st, _ := d.Status(ctx, "acme"); st.State != runtime.StateMissing {
		t.Fatalf("missing: %+v", st)
	}
	if err := d.Start(ctx, "acme"); !errors.Is(err, runtime.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := d.Create(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	st, _ := d.Status(ctx, "acme")
	if st.State != runtime.StateStopped || st.Endpoint != "reg-acme.regs.svc:5000" || st.PublicHost != "" {
		t.Fatalf("stopped: %+v", st)
	}

	if err := d.Start(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if st, _ := d.Status(ctx, "acme"); st.State != runtime.StateStarting {
		t.Fatalf("starting: %+v", st)
	}
	dep, _ := cs.AppsV1().Deployments(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
	dep.Status.ReadyReplicas = 1
	cs.AppsV1().Deployments(ns).UpdateStatus(ctx, dep, metav1.UpdateOptions{})
	if st, _ := d.Status(ctx, "acme"); st.State != runtime.StateRunning {
		t.Fatalf("running: %+v", st)
	}

	if err := d.Stop(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	dep, _ = cs.AppsV1().Deployments(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
	if *dep.Spec.Replicas != 0 {
		t.Fatal("not scaled to zero")
	}
}

func TestStopWaitsForPodsToTerminate(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	d.Create(ctx, spec())
	cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: d.labels("acme")}}, metav1.CreateOptions{})
	d.stopTimeout = 30 * time.Millisecond
	if err := d.Stop(ctx, "acme"); err == nil {
		t.Fatal("want timeout while the pod lingers")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cs.CoreV1().Pods(ns).Delete(ctx, "p", metav1.DeleteOptions{})
	}()
	d.stopTimeout = time.Second
	if err := d.Stop(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteKeepsOrRemovesData(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	d.Create(ctx, spec())

	if err := d.Delete(ctx, "acme", false); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.AppsV1().Deployments(ns).Get(ctx, "reg-acme", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deployment should be gone: %v", err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, "reg-acme-data", metav1.GetOptions{}); err != nil {
		t.Fatalf("data must survive: %v", err)
	}

	// recreate reuses the claim and rewrites the secret instead of failing
	s := spec()
	s.Files = s.Files[:1]
	if err := d.Create(ctx, s); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if sec, _ := cs.CoreV1().Secrets(ns).Get(ctx, "reg-acme-files", metav1.GetOptions{}); len(sec.Data) != 1 {
		t.Fatalf("stale secret keys: %v", sec.Data)
	}

	if err := d.Delete(ctx, "acme", true); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(ns).Get(ctx, "reg-acme-data", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pvc should be gone: %v", err)
	}
	if err := d.Delete(ctx, "acme", true); err != nil {
		t.Fatalf("delete must be idempotent: %v", err)
	}
}

func TestIngressExposure(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{Expose: ExposeIngress, Domain: "apps.example.com", IngressClass: "nginx", IngressTLSSecret: "wild"})
	s := spec()
	s.Env["REGISTRY_HTTP_TLS_CERTIFICATE"] = "/certs/tls.crt"
	if err := d.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	ing, err := cs.NetworkingV1().Ingresses(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ing.Spec.Rules[0].Host != "acme.apps.example.com" || *ing.Spec.IngressClassName != "nginx" || ing.Spec.TLS[0].SecretName != "wild" {
		t.Fatalf("ingress: %+v", ing.Spec)
	}
	if ing.Annotations["nginx.ingress.kubernetes.io/backend-protocol"] != "HTTPS" || ing.Annotations["nginx.ingress.kubernetes.io/proxy-body-size"] != "0" {
		t.Fatalf("annotations: %v", ing.Annotations)
	}
	if st, _ := d.Status(ctx, "acme"); st.PublicHost != "acme.apps.example.com" {
		t.Fatalf("public host: %+v", st)
	}
	d.Delete(ctx, "acme", true)
	if _, err := cs.NetworkingV1().Ingresses(ns).Get(ctx, "reg-acme", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("ingress not deleted")
	}
}

func TestRouteExposure(t *testing.T) {
	ctx := context.Background()
	d, _ := newDriver(t, Config{Expose: ExposeRoute, Domain: "apps.example.com"})

	route := func() map[string]any {
		u, err := d.dyn.Resource(routeGVR).Namespace(ns).Get(ctx, "reg-acme", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return u.Object["spec"].(map[string]any)
	}

	if err := d.Create(ctx, spec()); err != nil {
		t.Fatal(err)
	}
	sp := route()
	if sp["host"] != "acme.apps.example.com" || sp["tls"] != nil {
		t.Fatalf("plain route: %v", sp)
	}
	d.Delete(ctx, "acme", false)

	s := spec()
	s.Env["REGISTRY_HTTP_TLS_CERTIFICATE"] = "/certs/tls.crt"
	if err := d.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if tls, _ := route()["tls"].(map[string]any); tls["termination"] != "passthrough" {
		t.Fatalf("tls route must pass through: %v", route())
	}
	d.Delete(ctx, "acme", true)
	if _, err := d.dyn.Resource(routeGVR).Namespace(ns).Get(ctx, "reg-acme", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("route not deleted")
	}
}

// completeJobs makes created Jobs finish immediately, as succeeded or failed.
func completeJobs(cs *fake.Clientset, succeed bool) {
	cs.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, k8sruntime.Object, error) {
		j := a.(ktesting.CreateAction).GetObject().(*batchv1.Job)
		if succeed {
			j.Status.Succeeded = 1
		} else {
			j.Status.Failed = 1
		}
		return false, nil, nil // let the default tracker store the mutated object
	})
}

func TestRunGC(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	d.Create(ctx, spec())
	cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "gc-pod", Namespace: ns, Labels: map[string]string{"job-name": "reg-acme-gc"}}}, metav1.CreateOptions{})

	// refuses while the registry is meant to run
	d.Start(ctx, "acme")
	if _, err := d.RunGC(ctx, "acme"); err == nil {
		t.Fatal("must refuse while running")
	}
	d.Stop(ctx, "acme")

	var created *batchv1.Job
	cs.PrependReactor("create", "jobs", func(a ktesting.Action) (bool, k8sruntime.Object, error) {
		created = a.(ktesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		return false, nil, nil
	})
	completeJobs(cs, true)
	out, err := d.RunGC(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Fatal("expected pod logs")
	}
	c := created.Spec.Template.Spec.Containers[0]
	if len(c.Args) != 3 || c.Args[0] != "garbage-collect" || c.Args[1] != "--delete-untagged" || c.Command != nil || c.ReadinessProbe != nil {
		t.Fatalf("gc container: %+v", c)
	}
	if created.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever || created.Spec.Template.Labels[labelInstance] != "" {
		t.Fatalf("gc pod must not match the Service selector: %+v", created.Spec.Template)
	}
	if len(created.Spec.Template.Spec.Volumes) != 2 {
		t.Fatal("gc must mount the same data and config volumes")
	}
	if _, err := cs.BatchV1().Jobs(ns).Get(ctx, "reg-acme-gc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("job not cleaned up")
	}
}

func TestRunGCFailure(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	d.Create(ctx, spec())
	completeJobs(cs, false)
	if _, err := d.RunGC(ctx, "acme"); err == nil {
		t.Fatal("want failure")
	}
	if _, err := d.RunGC(ctx, "nope"); !errors.Is(err, runtime.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestUsedBytes(t *testing.T) {
	ctx := context.Background()
	d, cs := newDriver(t, Config{})
	d.Create(ctx, spec())

	if _, err := d.UsedBytes(ctx, "acme"); !errors.Is(err, runtime.ErrUnsupported) {
		t.Fatalf("no pod: %v", err)
	}
	cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns, Labels: d.labels("acme")},
		Spec:       corev1.PodSpec{NodeName: "node1"},
	}, metav1.CreateOptions{})

	d.stats = func(context.Context, string) ([]byte, error) {
		return []byte(`{"pods":[{"volume":[
			{"usedBytes":1,"pvcRef":{"name":"other","namespace":"regs"}},
			{"usedBytes":4242,"pvcRef":{"name":"reg-acme-data","namespace":"regs"}}]}]}`), nil
	}
	if n, err := d.UsedBytes(ctx, "acme"); err != nil || n != 4242 {
		t.Fatalf("got %d, %v", n, err)
	}

	d.stats = func(context.Context, string) ([]byte, error) { return nil, errors.New("forbidden") }
	if _, err := d.UsedBytes(ctx, "acme"); !errors.Is(err, runtime.ErrUnsupported) {
		t.Fatalf("forbidden: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(fake.NewClientset(), nil, Config{}); err == nil {
		t.Error("namespace required")
	}
	if _, err := New(fake.NewClientset(), nil, Config{Namespace: "x", Expose: ExposeIngress}); err == nil {
		t.Error("domain required when exposing")
	}
	if _, err := New(fake.NewClientset(), nil, Config{Namespace: "x", Expose: ExposeRoute, Domain: "d"}); err == nil {
		t.Error("route needs dynamic client")
	}
}

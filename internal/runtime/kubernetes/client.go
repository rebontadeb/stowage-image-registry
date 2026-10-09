package kubernetes

import (
	"os"
	"strings"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const nsFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Connect builds a Driver from an explicit kubeconfig path, or, when empty, from the in-cluster
// service account (falling back to the default kubeconfig chain for local development).
// An empty cfg.Namespace defaults to the pod's own namespace.
func Connect(kubeconfig string, cfg Config) (*Driver, error) {
	var rc *rest.Config
	var err error
	if kubeconfig == "" {
		if rc, err = rest.InClusterConfig(); err != nil {
			rules := clientcmd.NewDefaultClientConfigLoadingRules()
			if rc, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig(); err != nil {
				return nil, err
			}
		}
	} else if rc, err = clientcmd.BuildConfigFromFlags("", kubeconfig); err != nil {
		return nil, err
	}
	if cfg.Namespace == "" {
		if b, err := os.ReadFile(nsFile); err == nil {
			cfg.Namespace = strings.TrimSpace(string(b))
		}
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	var dyn dynamic.Interface
	if cfg.Expose == ExposeRoute {
		if dyn, err = dynamic.NewForConfig(rc); err != nil {
			return nil, err
		}
	}
	return New(cs, dyn, cfg)
}

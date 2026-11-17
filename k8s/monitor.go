package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/logger"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// debounceDelay coalesces bursts of Service events (e.g. a helm upgrade)
	// into a single update to the server.
	debounceDelay = 500 * time.Millisecond

	// resyncPeriod is how often the informer replays its cache as update
	// events, as a safety net.
	resyncPeriod = 10 * time.Minute

	syncTimeout = 30 * time.Second
)

// Callback receives the full list of annotated Services every time it changes.
type Callback func(containers []docker.Container)

// Monitor watches Kubernetes Services and reports those carrying Pangolin
// annotations.
type Monitor struct {
	client    kubernetes.Interface
	namespace string
	callback  Callback

	cancel context.CancelFunc
	lister listers.ServiceLister

	mu       sync.Mutex
	debounce *time.Timer
	stopped  bool
	lastSent []byte
}

// NewMonitor creates a Monitor. kubeconfig may be empty to use the in-cluster
// configuration, falling back to the default kubeconfig lookup (KUBECONFIG,
// ~/.kube/config). An empty namespace watches all namespaces.
func NewMonitor(kubeconfig, namespace string, callback Callback) (*Monitor, error) {
	cfg, err := buildConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load Kubernetes configuration: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return newMonitor(clientset, namespace, callback), nil
}

func newMonitor(client kubernetes.Interface, namespace string, callback Callback) *Monitor {
	return &Monitor{client: client, namespace: namespace, callback: callback}
}

func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// Start begins watching Services. It returns once the informer cache has
// synced (or fails after a timeout) and the callback has been invoked with the
// initial list. The informer reconnects on its own after API server errors.
func (m *Monitor) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	factory := informers.NewSharedInformerFactoryWithOptions(
		m.client,
		resyncPeriod,
		informers.WithNamespace(m.namespace), // "" means all namespaces
	)
	informer := factory.Core().V1().Services().Informer()
	m.lister = factory.Core().V1().Services().Lister()

	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { m.onEvent("add", obj) },
		UpdateFunc: func(oldObj, newObj interface{}) { m.onUpdate(oldObj, newObj) },
		DeleteFunc: func(obj interface{}) { m.onEvent("delete", obj) },
	})
	if err != nil {
		cancel()
		return fmt.Errorf("failed to register Service event handler: %w", err)
	}

	if m.namespace == "" {
		logger.Info("Starting Kubernetes Service monitoring for all namespaces")
	} else {
		logger.Info("Starting Kubernetes Service monitoring for namespace %q", m.namespace)
	}

	factory.Start(ctx.Done())

	syncCtx, syncCancel := context.WithTimeout(ctx, syncTimeout)
	defer syncCancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), informer.HasSynced) {
		cancel()
		return fmt.Errorf("timed out syncing Kubernetes Services (check the RBAC permissions to list and watch services)")
	}

	// Initial list
	m.notify()
	return nil
}

// Stop stops watching.
func (m *Monitor) Stop() {
	logger.Info("Stopping Kubernetes Service monitoring")
	m.mu.Lock()
	m.stopped = true
	if m.debounce != nil {
		m.debounce.Stop()
	}
	m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

// List returns the currently known annotated Services as containers.
func (m *Monitor) List() []docker.Container {
	if m.lister == nil {
		return nil
	}
	svcs, err := m.lister.List(labels.Everything())
	if err != nil {
		logger.Error("Failed to list Kubernetes Services: %v", err)
		return nil
	}
	return servicesToContainers(svcs)
}

func servicesToContainers(svcs []*corev1.Service) []docker.Container {
	containers := make([]docker.Container, 0)
	for _, svc := range svcs {
		if c, ok := ServiceToContainer(svc); ok {
			containers = append(containers, c)
		}
	}
	// Stable ordering so identical state yields an identical payload.
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	return containers
}

func (m *Monitor) onUpdate(oldObj, newObj interface{}) {
	oldSvc, ok1 := oldObj.(*corev1.Service)
	newSvc, ok2 := newObj.(*corev1.Service)
	if !ok1 || !ok2 {
		return
	}
	// Periodic resyncs replay unchanged objects; skip them.
	if oldSvc.ResourceVersion == newSvc.ResourceVersion {
		return
	}
	// Relevant if the Service is annotated now, or was before (annotations
	// removed).
	if !HasPangolinAnnotations(newSvc.Annotations) && !HasPangolinAnnotations(oldSvc.Annotations) {
		return
	}
	logger.Debug("Kubernetes Service event: update %s/%s", newSvc.Namespace, newSvc.Name)
	m.schedule()
}

func (m *Monitor) onEvent(action string, obj interface{}) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}
	svc, ok := obj.(*corev1.Service)
	if !ok || !HasPangolinAnnotations(svc.Annotations) {
		return
	}
	logger.Debug("Kubernetes Service event: %s %s/%s", action, svc.Namespace, svc.Name)
	m.schedule()
}

func (m *Monitor) schedule() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	if m.debounce != nil {
		m.debounce.Stop()
	}
	m.debounce = time.AfterFunc(debounceDelay, m.notify)
}

func (m *Monitor) notify() {
	containers := m.List()

	payload, err := json.Marshal(containers)
	if err != nil {
		logger.Error("Failed to encode Kubernetes Services: %v", err)
		return
	}

	m.mu.Lock()
	if m.stopped || bytes.Equal(payload, m.lastSent) {
		m.mu.Unlock()
		return
	}
	m.lastSent = payload
	m.mu.Unlock()

	logger.Debug("Triggering callback with %d Kubernetes Services", len(containers))
	m.callback(containers)
}

package k8s

import (
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/fosrl/newt/docker"
)

func TestAnnotationsToLabels_Dotted(t *testing.T) {
	labels, warnings := AnnotationsToLabels(map[string]string{
		"pangolin.public-resources.web.name":                       "Web",
		"pangolin.public-resources.web.targets.0.port":             "8080",
		"pangolin.net/public-resources.web.targets.1.hostname":     "other",
		"pangolin.net/public-resources.web.auth.sso-roles.0":       "Member",
		"pangolin.private-resources.123.destination":               "10.0.0.1",
		"pangolin.public-resources.web.targets.0.healthcheck.port": "9000",
		"unrelated.example.com/annotation":                         "ignored",
		"kubectl.kubernetes.io/last-applied-configuration":         "ignored",
	})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := map[string]string{
		"pangolin.public-resources.web.name":                        "Web",
		"pangolin.public-resources.web.targets[0].port":             "8080",
		"pangolin.public-resources.web.targets[1].hostname":         "other",
		"pangolin.public-resources.web.auth.sso-roles[0]":           "Member",
		"pangolin.private-resources.123.destination":                "10.0.0.1",
		"pangolin.public-resources.web.targets[0].healthcheck.port": "9000",
	}
	if !reflect.DeepEqual(labels, want) {
		t.Fatalf("got %v\nwant %v", labels, want)
	}
}

func TestAnnotationsToLabels_Blueprint(t *testing.T) {
	labels, warnings := AnnotationsToLabels(map[string]string{
		"pangolin.net/blueprint": `
public-resources:
  web:
    name: Web
    protocol: http
    full-domain: web.example.com
    ssl: true
    auth:
      sso-roles:
        - Member
    targets:
      - method: http
        port: 8080
`,
		// individual annotations win over the blueprint
		"pangolin.net/public-resources.web.name": "Override",
	})
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := map[string]string{
		"pangolin.public-resources.web.name":              "Override",
		"pangolin.public-resources.web.protocol":          "http",
		"pangolin.public-resources.web.full-domain":       "web.example.com",
		"pangolin.public-resources.web.ssl":               "true",
		"pangolin.public-resources.web.auth.sso-roles[0]": "Member",
		"pangolin.public-resources.web.targets[0].method": "http",
		"pangolin.public-resources.web.targets[0].port":   "8080",
	}
	if !reflect.DeepEqual(labels, want) {
		t.Fatalf("got %v\nwant %v", labels, want)
	}
}

func TestAnnotationsToLabels_Invalid(t *testing.T) {
	labels, warnings := AnnotationsToLabels(map[string]string{
		"pangolin.public-resources.web":            "x", // too short
		"pangolin.other-section.web.name":          "x", // unknown section
		"pangolin.public-resources.web.0":          "x", // index as property
		"pangolin.net/blueprint":                   "public-resources: [",
		"pangolin.public-resources.ok.full-domain": "ok.example.com",
	})
	if len(warnings) != 4 {
		t.Fatalf("expected 4 warnings, got %d: %v", len(warnings), warnings)
	}
	if len(labels) != 1 || labels["pangolin.public-resources.ok.full-domain"] != "ok.example.com" {
		t.Fatalf("unexpected labels: %v", labels)
	}
}

func testService(name, ns string, annotations map[string]string, ports ...int32) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			UID:         types.UID("0123456789abcdef-uid"),
			Annotations: annotations,
		},
	}
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: p, Protocol: corev1.ProtocolTCP})
	}
	return svc
}

func TestServiceToContainer(t *testing.T) {
	svc := testService("web", "apps", map[string]string{
		"pangolin.public-resources.web.full-domain": "web.example.com",
	}, 8080, 9090)

	c, ok := ServiceToContainer(svc)
	if !ok {
		t.Fatal("expected annotated service to convert")
	}
	if c.Name != "web.apps.svc" || c.State != "running" || c.ID != "0123456789ab" {
		t.Fatalf("unexpected container: %+v", c)
	}
	if len(c.Ports) != 2 || c.Ports[0].PrivatePort != 8080 || c.Ports[0].Type != "tcp" {
		t.Fatalf("unexpected ports: %+v", c.Ports)
	}
	if c.Labels["pangolin.public-resources.web.full-domain"] != "web.example.com" {
		t.Fatalf("unexpected labels: %v", c.Labels)
	}

	if _, ok := ServiceToContainer(testService("plain", "apps", map[string]string{"foo": "bar"}, 80)); ok {
		t.Fatal("service without pangolin annotations must be skipped")
	}

	now := metav1.Now()
	deleting := testService("gone", "apps", svc.Annotations, 80)
	deleting.DeletionTimestamp = &now
	if _, ok := ServiceToContainer(deleting); ok {
		t.Fatal("service being deleted must be skipped")
	}
}

func TestMonitorReportsServiceChanges(t *testing.T) {
	annotated := map[string]string{"pangolin.public-resources.web.full-domain": "web.example.com"}
	client := fake.NewSimpleClientset(
		testService("web", "apps", annotated, 80),
		testService("plain", "apps", nil, 80),
		testService("other", "elsewhere", annotated, 80),
	)

	updates := make(chan []docker.Container, 8)
	m := newMonitor(client, "apps", func(c []docker.Container) { updates <- c })
	if err := m.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer m.Stop()

	next := func() []docker.Container {
		t.Helper()
		select {
		case c := <-updates:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for update")
			return nil
		}
	}

	// Initial list is limited to the namespace and to annotated Services.
	got := next()
	if len(got) != 1 || got[0].Name != "web.apps.svc" {
		t.Fatalf("unexpected initial list: %+v", got)
	}

	// Adding an annotated Service triggers an update.
	if _, err := client.CoreV1().Services("apps").Create(t.Context(), testService("api", "apps", annotated, 8000), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got = next()
	if len(got) != 2 {
		t.Fatalf("expected 2 services after add, got %+v", got)
	}

	// Deleting a Service drops it from the list.
	if err := client.CoreV1().Services("apps").Delete(t.Context(), "api", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	got = next()
	if len(got) != 1 || got[0].Name != "web.apps.svc" {
		t.Fatalf("expected only web after delete, got %+v", got)
	}
}

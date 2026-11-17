package k8s

import (
	"fmt"
	"strings"

	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/logger"
	corev1 "k8s.io/api/core/v1"
)

// ServiceToContainer converts a Kubernetes Service carrying Pangolin
// annotations into a docker.Container so the existing label based blueprint
// pipeline on the server can be reused unchanged.
//
// The container name is the in-cluster DNS name of the Service
// (<name>.<namespace>.svc), which is what the server uses as the default target
// hostname, and the Service ports populate the container ports so the first
// Service port becomes the default target port.
//
// ok is false when the Service has no Pangolin annotations or is being deleted.
func ServiceToContainer(svc *corev1.Service) (c docker.Container, ok bool) {
	if svc == nil || svc.DeletionTimestamp != nil || !HasPangolinAnnotations(svc.Annotations) {
		return docker.Container{}, false
	}

	labels, warnings := AnnotationsToLabels(svc.Annotations)
	for _, w := range warnings {
		logger.Warn("Service %s/%s: %v", svc.Namespace, svc.Name, w)
	}

	ports := make([]docker.Port, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		ports = append(ports, docker.Port{
			PrivatePort: int(p.Port),
			Type:        strings.ToLower(string(p.Protocol)),
		})
	}

	name := fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace)

	id := string(svc.UID)
	if len(id) > 12 {
		id = id[:12]
	}

	return docker.Container{
		ID:       id,
		Name:     name,
		State:    "running",
		Status:   "Service",
		Ports:    ports,
		Labels:   labels,
		Created:  svc.CreationTimestamp.Unix(),
		Networks: map[string]docker.Network{},
		Hostname: name,
	}, true
}

package newt

import (
	"github.com/fosrl/newt/docker"
	"github.com/fosrl/newt/logger"
)

// kubernetesServices returns the annotated Kubernetes Services as containers,
// or nil when Kubernetes monitoring is not running.
func (n *Newt) kubernetesServices() []docker.Container {
	if n.k8sMonitor == nil {
		return nil
	}
	return n.k8sMonitor.List()
}

// containerSourcesEnabled reports whether Docker or Kubernetes is configured.
func (n *Newt) containerSourcesEnabled() bool {
	return n.config.DockerSocket != "" || n.k8sMonitor != nil
}

// collectContainers returns the combined, freshly gathered list of Docker
// containers and Kubernetes Services. The server treats this list as the full
// desired state, so both sources must be included in every update.
func (n *Newt) collectContainers() ([]docker.Container, error) {
	containers := []docker.Container{}

	if n.config.DockerSocket != "" {
		dockerContainers, err := docker.ListContainers(n.config.DockerSocket, n.config.DockerEnforceNetworkValidation)
		if err != nil {
			return nil, err
		}
		containers = append(containers, dockerContainers...)
	}

	return append(containers, n.kubernetesServices()...), nil
}

// sendContainers sends the container list to the server.
func (n *Newt) sendContainers(containers []docker.Container) error {
	return n.client.SendMessage("newt/socket/containers", map[string]interface{}{
		"containers": containers,
	})
}

// onDockerContainers handles a changed Docker container list.
func (n *Newt) onDockerContainers(dockerContainers []docker.Container) {
	containers := append(append([]docker.Container{}, dockerContainers...), n.kubernetesServices()...)
	logger.Debug("Docker event detected, sending updated container list (%d containers)", len(containers))
	if err := n.sendContainers(containers); err != nil {
		logger.Error("Failed to send updated container list after Docker event: %v", err)
	} else {
		logger.Debug("Updated container list sent successfully")
	}
}

// onKubernetesServices handles a changed Kubernetes Service list.
func (n *Newt) onKubernetesServices(_ []docker.Container) {
	containers, err := n.collectContainers()
	if err != nil {
		logger.Error("Failed to list containers after Kubernetes Service change: %v", err)
		return
	}
	logger.Debug("Kubernetes Service change detected, sending updated container list (%d entries)", len(containers))
	if err := n.sendContainers(containers); err != nil {
		logger.Error("Failed to send updated container list after Kubernetes Service change: %v", err)
	}
}

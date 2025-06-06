package docker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/fosrl/newt/logger"
)

// Container represents a Docker container
type Container struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Image    string             `json:"image"`
	State    string             `json:"state"`
	Status   string             `json:"status"`
	Ports    []Port             `json:"ports"`
	Labels   map[string]string  `json:"labels"`
	Created  int64              `json:"created"`
	Networks map[string]Network `json:"networks"`
}

// Port represents a port mapping for a Docker container
type Port struct {
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

// Network represents network information for a Docker container
type Network struct {
	NetworkID           string   `json:"networkId"`
	EndpointID          string   `json:"endpointId"`
	Gateway             string   `json:"gateway,omitempty"`
	IPAddress           string   `json:"ipAddress,omitempty"`
	IPPrefixLen         int      `json:"ipPrefixLen,omitempty"`
	IPv6Gateway         string   `json:"ipv6Gateway,omitempty"`
	GlobalIPv6Address   string   `json:"globalIPv6Address,omitempty"`
	GlobalIPv6PrefixLen int      `json:"globalIPv6PrefixLen,omitempty"`
	MacAddress          string   `json:"macAddress,omitempty"`
	Aliases             []string `json:"aliases,omitempty"`
	DNSNames            []string `json:"dnsNames,omitempty"`
}

// CheckSocket checks if Docker socket is available
func CheckSocket(socketPath string) bool {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Try to create a connection to the Docker socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		logger.Debug("Docker socket not available at %s: %v", socketPath, err)
		return false
	}
	defer conn.Close()

	logger.Debug("Docker socket is available at %s", socketPath)
	return true
}

// ListContainers lists all Docker containers with their network information
func ListContainers(socketPath string, labelEnable bool) ([]Container, error) {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Create a new Docker client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create client with custom socket path
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// List containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %v", err)
	}

	var dockerContainers []Container
	for _, c := range containers {
		// Get container name (remove leading slash)
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		// If label enable functionality is on, if no label found with a "true" value, then we skip that one
		if labelEnable {
			labelEnableValue, ok := c.Labels["newt.docker.enable"]
			if !ok || !strings.Contains(strings.ToLower(labelEnableValue), "true") {
				logger.Debug("Container %s does not have required label to be used by pangolin", name)
				continue
			} else {
				logger.Debug("Container %s has required label to be used by pangolin", name)
			}
		}

		// Convert ports
		var ports []Port
		for _, port := range c.Ports {
			dockerPort := Port{
				PrivatePort: int(port.PrivatePort),
				Type:        port.Type,
			}
			if port.PublicPort != 0 {
				dockerPort.PublicPort = int(port.PublicPort)
			}
			if port.IP != "" {
				dockerPort.IP = port.IP
			}
			ports = append(ports, dockerPort)
		}

		// Get network information by inspecting the container
		networks := make(map[string]Network)

		// Inspect container to get detailed network information
		containerInfo, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			logger.Debug("Failed to inspect container %s for network info: %v", c.ID[:12], err)
			// Continue without network info if inspection fails
		} else {
			// Extract network information from inspection
			if containerInfo.NetworkSettings != nil && containerInfo.NetworkSettings.Networks != nil {
				for networkName, endpoint := range containerInfo.NetworkSettings.Networks {
					dockerNetwork := Network{
						NetworkID:           endpoint.NetworkID,
						EndpointID:          endpoint.EndpointID,
						Gateway:             endpoint.Gateway,
						IPAddress:           endpoint.IPAddress,
						IPPrefixLen:         endpoint.IPPrefixLen,
						IPv6Gateway:         endpoint.IPv6Gateway,
						GlobalIPv6Address:   endpoint.GlobalIPv6Address,
						GlobalIPv6PrefixLen: endpoint.GlobalIPv6PrefixLen,
						MacAddress:          endpoint.MacAddress,
						Aliases:             endpoint.Aliases,
						DNSNames:            endpoint.DNSNames,
					}
					networks[networkName] = dockerNetwork
				}
			}
		}

		dockerContainer := Container{
			ID:       c.ID[:12], // Show short ID like docker ps
			Name:     name,
			Image:    c.Image,
			State:    c.State,
			Status:   c.Status,
			Ports:    ports,
			Labels:   c.Labels,
			Created:  c.Created,
			Networks: networks,
		}
		dockerContainers = append(dockerContainers, dockerContainer)
	}

	return dockerContainers, nil
}

package docker

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
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
	Hostname string             `json:"hostname"` // added to use hostname if available instead of network address

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

// Strcuture parts of docker api endpoint
type dockerHost struct {
	protocol string // e.g. unix, http, tcp, ssh
	address  string // e.g. "/var/run/docker.sock" or "host:port"
}

// Parse the docker api endpoint into its parts
func parseDockerHost(raw string) (dockerHost, error) {
	switch {
	case strings.HasPrefix(raw, "unix://"):
		return dockerHost{"unix", strings.TrimPrefix(raw, "unix://")}, nil
	case strings.HasPrefix(raw, "ssh://"):
		// SSH is treated as TCP-like transport by the docker client
		return dockerHost{"ssh", strings.TrimPrefix(raw, "ssh://")}, nil
	case strings.HasPrefix(raw, "tcp://"), strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		s := raw
		s = strings.TrimPrefix(s, "tcp://")
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "https://")
		return dockerHost{"tcp", s}, nil
	case strings.HasPrefix(raw, "/"):
		// Absolute path without scheme - treat as unix socket
		return dockerHost{"unix", raw}, nil
	default:
		// For relative paths or other formats, also default to unix
		return dockerHost{"unix", raw}, nil
	}
}

// CheckSocket checks if Docker socket is available
func CheckSocket(socketPath string) bool {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "unix:///var/run/docker.sock"
	}

	// Ensure the socket path is properly formatted
	if !strings.Contains(socketPath, "://") {
		// If no scheme provided, assume unix socket
		socketPath = "unix://" + socketPath
	}

	host, err := parseDockerHost(socketPath)
	if err != nil {
		logger.Debug("Invalid Docker socket path '%s': %v", socketPath, err)
		return false
	}
	protocol := host.protocol
	addr := host.address

	// ssh might need different verification, but tcp works for basic reachability
	conn, err := net.DialTimeout(protocol, addr, 2*time.Second)
	if err != nil {
		logger.Debug("Docker not reachable via %s at %s: %v", protocol, addr, err)
		return false
	}
	defer conn.Close()

	logger.Debug("Docker reachable via %s at %s", protocol, addr)
	return true
}

// IsWithinHostNetwork checks if a provided target is within the host container network
func IsWithinHostNetwork(socketPath string, targetAddress string, targetPort int) (bool, error) {
	// Always enforce network validation
	containers, err := ListContainers(socketPath, true)
	if err != nil {
		return false, err
	}

	// Determine if given an IP address
	var parsedTargetAddressIp = net.ParseIP(targetAddress)

	// If we can find the passed hostname/IP address in the networks or as the container name, it is valid and can add it
	for _, c := range containers {
		for _, network := range c.Networks {
			// If the target address is not an IP address, use the container name
			if parsedTargetAddressIp == nil {
				if c.Name == targetAddress {
					for _, port := range c.Ports {
						if port.PublicPort == targetPort || port.PrivatePort == targetPort {
							return true, nil
						}
					}
				}
			} else {
				//If the IP address matches, check the ports being mapped too
				if network.IPAddress == targetAddress {
					for _, port := range c.Ports {
						if port.PublicPort == targetPort || port.PrivatePort == targetPort {
							return true, nil
						}
					}
				}
			}
		}
	}

	combinedTargetAddress := targetAddress + ":" + strconv.Itoa(targetPort)
	return false, fmt.Errorf("target address not within host container network: %s", combinedTargetAddress)
}

// ListContainers lists all Docker containers with their network information
func ListContainers(socketPath string, enforceNetworkValidation bool) ([]Container, error) {
	// Use the provided socket path or default to standard location
	if socketPath == "" {
		socketPath = "unix:///var/run/docker.sock"
	}

	// Ensure the socket path is properly formatted for the Docker client
	if !strings.Contains(socketPath, "://") {
		// If no scheme provided, assume unix socket
		socketPath = "unix://" + socketPath
	}

	// Used to filter down containers returned to Pangolin
	containerFilters := filters.NewArgs()

	// Used to determine if we will send IP addresses or hostnames to Pangolin
	useContainerIpAddresses := true
	hostContainerId := ""

	// Create a new Docker client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create client with custom socket path
	cli, err := client.NewClientWithOpts(
		client.WithHost(socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	defer cli.Close()

	hostContainer, err := getHostContainer(ctx, cli)
	if enforceNetworkValidation && err != nil {
		return nil, fmt.Errorf("network validation enforced, cannot validate due to: %w", err)
	}

	// We may not be able to get back host container in scenarios like running the container in network mode 'host'
	if hostContainer != nil {
		// We can use the host container to filter out the list of returned containers
		hostContainerId = hostContainer.ID

		for hostContainerNetworkName := range hostContainer.NetworkSettings.Networks {
			// If we're enforcing network validation, we'll filter on the host containers networks
			if enforceNetworkValidation {
				containerFilters.Add("network", hostContainerNetworkName)
			}

			// If the container is on the docker bridge network, we will use IP addresses over hostnames
			if useContainerIpAddresses && hostContainerNetworkName != "bridge" {
				useContainerIpAddresses = false
			}
		}
	}

	// List containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: containerFilters})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %v", err)
	}

	var dockerContainers []Container
	for _, c := range containers {
		// Short ID like docker ps
		shortId := c.ID[:12]

		// Inspect container to get hostname
		hostname := ""
		containerInfo, err := cli.ContainerInspect(ctx, c.ID)
		if err == nil && containerInfo.Config != nil {
			hostname = containerInfo.Config.Hostname
		}

		// Skip host container if set
		if hostContainerId != "" && c.ID == hostContainerId {
			continue
		}

		// Get container name (remove leading slash)
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
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

		// Extract network information from inspection
		if c.NetworkSettings != nil && c.NetworkSettings.Networks != nil {
			for networkName, endpoint := range c.NetworkSettings.Networks {
				dockerNetwork := Network{
					NetworkID:           endpoint.NetworkID,
					EndpointID:          endpoint.EndpointID,
					Gateway:             endpoint.Gateway,
					IPPrefixLen:         endpoint.IPPrefixLen,
					IPv6Gateway:         endpoint.IPv6Gateway,
					GlobalIPv6Address:   endpoint.GlobalIPv6Address,
					GlobalIPv6PrefixLen: endpoint.GlobalIPv6PrefixLen,
					MacAddress:          endpoint.MacAddress,
					Aliases:             endpoint.Aliases,
					DNSNames:            endpoint.DNSNames,
				}

				// Use IPs over hostnames/containers as we're on the bridge network
				if useContainerIpAddresses {
					dockerNetwork.IPAddress = endpoint.IPAddress
				}

				networks[networkName] = dockerNetwork
			}
		}

		dockerContainer := Container{
			ID:       shortId,
			Name:     name,
			Image:    c.Image,
			State:    c.State,
			Status:   c.Status,
			Ports:    ports,
			Labels:   c.Labels,
			Created:  c.Created,
			Networks: networks,
			Hostname: hostname, // added
		}

		dockerContainers = append(dockerContainers, dockerContainer)
	}

	return dockerContainers, nil
}

// getHostContainer gets the current container for the current host if possible
func getHostContainer(dockerContext context.Context, dockerClient *client.Client) (*container.InspectResponse, error) {
	// Get hostname from the os
	hostContainerName, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to find hostname for container")
	}

	// Get host container from the docker socket
	hostContainer, err := dockerClient.ContainerInspect(dockerContext, hostContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to find host container")
	}

	return &hostContainer, nil
}

// EventCallback defines the function signature for handling Docker events
type EventCallback func(containers []Container)

// EventMonitor handles Docker event monitoring
type EventMonitor struct {
	client                   *client.Client
	ctx                      context.Context
	cancel                   context.CancelFunc
	callback                 EventCallback
	socketPath               string
	enforceNetworkValidation bool
}

// NewEventMonitor creates a new Docker event monitor
func NewEventMonitor(socketPath string, enforceNetworkValidation bool, callback EventCallback) (*EventMonitor, error) {
	if socketPath == "" {
		socketPath = "unix:///var/run/docker.sock"
	}

	if !strings.Contains(socketPath, "://") {
		socketPath = "unix://" + socketPath
	}

	cli, err := client.NewClientWithOpts(
		client.WithHost(socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &EventMonitor{
		client:                   cli,
		ctx:                      ctx,
		cancel:                   cancel,
		callback:                 callback,
		socketPath:               socketPath,
		enforceNetworkValidation: enforceNetworkValidation,
	}, nil
}

// Start begins monitoring Docker events
func (em *EventMonitor) Start() error {
	logger.Debug("Starting Docker event monitoring")

	// Filter for container events we care about
	eventFilters := filters.NewArgs()
	eventFilters.Add("type", "container")
	// eventFilters.Add("event", "create")
	eventFilters.Add("event", "start")
	eventFilters.Add("event", "stop")
	// eventFilters.Add("event", "destroy")
	// eventFilters.Add("event", "die")
	// eventFilters.Add("event", "pause")
	// eventFilters.Add("event", "unpause")

	// Start listening for events
	eventCh, errCh := em.client.Events(em.ctx, events.ListOptions{
		Filters: eventFilters,
	})

	go func() {
		defer func() {
			if err := em.client.Close(); err != nil {
				logger.Error("Error closing Docker client: %v", err)
			}
		}()

		for {
			select {
			case event := <-eventCh:
				logger.Debug("Docker event received: %s %s for container %s", event.Action, event.Type, event.Actor.ID[:12])

				// Fetch updated container list and trigger callback
				go em.handleEvent(event)

			case err := <-errCh:
				if err != nil && err != context.Canceled {
					logger.Error("Docker event stream error: %v", err)
					// Try to reconnect after a brief delay
					time.Sleep(5 * time.Second)
					if em.ctx.Err() == nil {
						logger.Info("Attempting to reconnect to Docker event stream")
						eventCh, errCh = em.client.Events(em.ctx, events.ListOptions{
							Filters: eventFilters,
						})
					}
				}
				return

			case <-em.ctx.Done():
				logger.Info("Docker event monitoring stopped")
				return
			}
		}
	}()

	return nil
}

// handleEvent processes a Docker event and triggers the callback with updated container list
func (em *EventMonitor) handleEvent(event events.Message) {
	// Add a small delay to ensure Docker has fully processed the event
	time.Sleep(100 * time.Millisecond)

	containers, err := ListContainers(em.socketPath, em.enforceNetworkValidation)
	if err != nil {
		logger.Error("Failed to list containers after Docker event %s: %v", event.Action, err)
		return
	}

	logger.Debug("Triggering callback with %d containers after Docker event %s", len(containers), event.Action)
	em.callback(containers)
}

// Stop stops the event monitoring
func (em *EventMonitor) Stop() {
	logger.Info("Stopping Docker event monitoring")
	if em.cancel != nil {
		em.cancel()
	}
}

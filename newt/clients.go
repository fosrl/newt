package newt

import (
	"strings"

	wgnetstack "github.com/fosrl/newt/clients"
	"github.com/fosrl/newt/clients/permissions"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func checkNativeMainPermissions() error {
	return permissions.CheckNativeInterfacePermissions()
}

func (n *Newt) setupClients() {
	host := n.config.Endpoint
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}
	host = strings.TrimSuffix(host, "/")

	logger.Debug("Setting up clients with netstack2...")

	if n.config.UseNativeInterface {
		logger.Debug("Checking permissions for native interface")
		if err := permissions.CheckNativeInterfacePermissions(); err != nil {
			logger.Fatal("Insufficient permissions to create native TUN interface: %v", err)
			return
		}
	}

	var err error
	n.wgService, err = wgnetstack.NewWireGuardService(
		n.config.InterfaceName,
		n.config.Port,
		n.config.MTU,
		host,
		n.config.ID,
		n.client,
		n.config.DNS,
		n.config.UseNativeInterface,
	)
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	n.wgService.SetCredentialStore(n.sshCredStore)

	n.client.OnTokenUpdate(func(token string) {
		n.wgService.SetToken(token)
	})

	n.ready = true
}

func (n *Newt) setDownstreamTNetstack(tnet *netstack.Net) {
	if n.wgService != nil {
		n.wgService.SetOthertnet(tnet)
	}
}

func (n *Newt) closeClients() {
	logger.Info("Closing clients...")
	if n.wgService != nil {
		n.wgService.Close()
		n.wgService = nil
	}
}

func (n *Newt) setClientsBlocked(v bool) {
	if n.wgService != nil {
		n.wgService.SetBlocked(v)
	}
}

func (n *Newt) clientsHandleNewtConnection(publicKey string, endpoint string, relayPort uint16) {
	if !n.ready {
		return
	}

	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		logger.Error("Invalid endpoint format: %s", endpoint)
		return
	}
	endpoint = strings.Join(parts[:len(parts)-1], ":")

	if n.wgService != nil {
		n.wgService.StartHolepunch(publicKey, endpoint, relayPort)
	}
}

func (n *Newt) clientsOnConnect() {
	if !n.ready {
		return
	}
	if n.wgService != nil {
		n.wgService.LoadRemoteConfig()
	}
}

// localEndpoints returns "ip:port" candidates on this host that could
// potentially be used to reach our WireGuard listen port, ranked with the
// most likely genuine host interfaces first.
func (n *Newt) localEndpoints() []string {
	return network.GetLocalEndpoints(n.config.Port, n.config.InterfaceName)
}

func (n *Newt) clientsStartDirectRelay(tunnelIP string) {
	if !n.ready {
		return
	}
	if n.wgService != nil {
		if err := n.wgService.StartDirectUDPRelay(tunnelIP); err != nil {
			logger.Error("Failed to start direct UDP relay: %v", err)
		}
	}
}

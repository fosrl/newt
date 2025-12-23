package main

import (
	"strings"

	"github.com/fosrl/newt/clients"
	wgnetstack "github.com/fosrl/newt/clients"
	"github.com/fosrl/newt/clients/permissions"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var wgService *clients.WireGuardService
var ready bool

func setupClients(client *websocket.Client) {
	var host = endpoint
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	host = strings.TrimSuffix(host, "/")

	logger.Debug("Setting up clients with netstack2...")

	// if useNativeInterface is true make sure we have permission to use native interface
	if useNativeInterface {
		logger.Debug("Checking permissions for native interface")
		err := permissions.CheckNativeInterfacePermissions()
		if err != nil {
			logger.Fatal("Insufficient permissions to create native TUN interface: %v", err)
			return
		}
	}

	// Create WireGuard service
	wgService, err = wgnetstack.NewWireGuardService(interfaceName, port, mtuInt, host, id, client, dns, useNativeInterface)
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	client.OnTokenUpdate(func(token string) {
		wgService.SetToken(token)
	})

	ready = true
}

func setDownstreamTNetstack(tnet *netstack.Net) {
	if wgService != nil {
		wgService.SetOthertnet(tnet)
	}
}

func closeClients() {
	logger.Info("Closing clients...")
	if wgService != nil {
		wgService.Close()
		wgService = nil
	}
}

func clientsHandleNewtConnection(publicKey string, endpoint string, relayPort uint16) {
	if !ready {
		return
	}

	// split off the port from the endpoint
	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		logger.Error("Invalid endpoint format: %s", endpoint)
		return
	}
	endpoint = strings.Join(parts[:len(parts)-1], ":")

	if wgService != nil {
		wgService.StartHolepunch(publicKey, endpoint, relayPort)
	}
}

func clientsOnConnect() {
	if !ready {
		return
	}
	if wgService != nil {
		wgService.LoadRemoteConfig()
	}
}

// clientsStartDirectRelay starts a direct UDP relay from the main tunnel netstack
// to the clients' WireGuard, bypassing the proxy for better performance.
func clientsStartDirectRelay(tunnelIP string) {
	if !ready {
		return
	}
	if wgService != nil {
		if err := wgService.StartDirectUDPRelay(tunnelIP); err != nil {
			logger.Error("Failed to start direct UDP relay: %v", err)
		}
	}
}

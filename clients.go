package main

import (
	"fmt"
	"strings"

	"github.com/fosrl/newt/clients"
	wgnetstack "github.com/fosrl/newt/clients"
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/netstack2"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/fosrl/newt/wgtester"
)

var wgService *clients.WireGuardService
var wgTesterServer *wgtester.Server
var ready bool

func setupClients(client *websocket.Client) {
	var host = endpoint
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	host = strings.TrimSuffix(host, "/")

	logger.Info("Setting up clients with netstack2...")
	// Create WireGuard service
	wgService, err = wgnetstack.NewWireGuardService(interfaceName, mtuInt, generateAndSaveKeyTo, host, id, client, "9.9.9.9", useNativeInterface)
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	// // Set up callback to restart wgtester with netstack when WireGuard is ready
	wgService.SetOnNetstackReady(func(tnet *netstack2.Net) {

		wgTesterServer = wgtester.NewServerWithNetstack("0.0.0.0", wgService.Port, id, tnet) // TODO: maybe make this the same ip of the wg server?
		err := wgTesterServer.Start()
		if err != nil {
			logger.Error("Failed to start WireGuard tester server: %v", err)
		}
	})

	wgService.SetOnNetstackClose(func() {
		if wgTesterServer != nil {
			wgTesterServer.Stop()
			wgTesterServer = nil
		}
	})

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

	if wgTesterServer != nil {
		wgTesterServer.Stop()
		wgTesterServer = nil
	}
}

func clientsHandleNewtConnection(publicKey string, endpoint string) {
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
		wgService.StartHolepunch(publicKey, endpoint)
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

func clientsAddProxyTarget(pm *proxy.ProxyManager, tunnelIp string) {
	if !ready {
		return
	}
	// add a udp proxy for localost and the wgService port
	// TODO: make sure this port is not used in a target
	if wgService != nil {
		pm.AddTarget("udp", tunnelIp, int(wgService.Port), fmt.Sprintf("127.0.0.1:%d", wgService.Port))
	}
}

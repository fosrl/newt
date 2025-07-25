//go:build linux

package main

import (
	"fmt"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"golang.zx2c4.com/wireguard/tun/netstack"

	// "github.com/fosrl/newt/wg"
	"github.com/fosrl/newt/wgnetstack"
	"github.com/fosrl/newt/wgtester"
)

var wgService *wgnetstack.WireGuardService
var wgTesterServer *wgtester.Server

func setupClients(client *websocket.Client) {
	var host = endpoint
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	host = strings.TrimSuffix(host, "/")

	// Create WireGuard service
	wgService, err = wgnetstack.NewWireGuardService(interfaceName, mtuInt, generateAndSaveKeyTo, host, id, client, "8.8.8.8")
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	// // Set up callback to restart wgtester with netstack when WireGuard is ready
	wgService.SetOnNetstackReady(func(tnet *netstack.Net) {

		wgTesterServer = wgtester.NewServerWithNetstack("0.0.0.0", wgService.Port, id, tnet) // TODO: maybe make this the same ip of the wg server?
		err := wgTesterServer.Start()
		if err != nil {
			logger.Error("Failed to start WireGuard tester server: %v", err)
		}
		// 	logger.Info("WireGuard netstack is ready, restarting wgtester with netstack")
		// 	if err := wgTesterServer.RestartWithNetstack(tnet); err != nil {
		// 		logger.Error("Failed to restart wgtester with netstack: %v", err)
		// 	} else {
		// 		logger.Info("WGTester successfully restarted with netstack")
		// 	}
	})

	client.OnTokenUpdate(func(token string) {
		wgService.SetToken(token)
	})
}

func closeClients() {
	if wgService != nil {
		wgService.Close(!keepInterface)
		wgService = nil
	}

	if wgTesterServer != nil {
		wgTesterServer.Stop()
		wgTesterServer = nil
	}
}

func clientsHandleNewtConnection(publicKey string, endpoint string) {
	if wgService == nil {
		return
	}

	// split off the port from the endpoint
	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		logger.Error("Invalid endpoint format: %s", endpoint)
		return
	}
	endpoint = strings.Join(parts[:len(parts)-1], ":")

	wgService.StartHolepunch(publicKey, endpoint)
}

func clientsOnConnect() {
	if wgService == nil {
		return
	}
	wgService.LoadRemoteConfig()
}

func clientsAddProxyTarget(pm *proxy.ProxyManager, tunnelIp string) {
	if wgService == nil {
		return
	}
	// add a udp proxy for localost and the wgService port
	// TODO: make sure this port is not used in a target
	pm.AddTarget("udp", tunnelIp, int(wgService.Port), fmt.Sprintf("127.0.0.1:%d", wgService.Port))
}

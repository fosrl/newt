//go:build linux

package main

import (
	"fmt"
	"strings"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"github.com/fosrl/newt/wg"
	"github.com/fosrl/newt/wgtester"
)

var wgService *wg.WireGuardService
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
	wgService, err = wg.NewWireGuardService(interfaceName, mtuInt, generateAndSaveKeyTo, host, id, client)
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	wgTesterServer = wgtester.NewServer("0.0.0.0", wgService.Port, id) // TODO: maybe make this the same ip of the wg server?
	err := wgTesterServer.Start()
	if err != nil {
		logger.Error("Failed to start WireGuard tester server: %v", err)
	}

	client.OnTokenUpdate(func(token string) {
		wgService.SetToken(token)
	})
}

func closeClients() {
	if wgService != nil {
		wgService.Close(rm)
		wgService = nil
	}

	if wgTesterServer != nil {
		wgTesterServer.Stop()
		wgTesterServer = nil
	}
}

func clientsHandleNewtConnection(publicKey string) {
	if wgService == nil {
		return
	}
	wgService.SetServerPubKey(publicKey)
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

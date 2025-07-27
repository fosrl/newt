//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
	"github.com/fosrl/newt/wg"
	"github.com/fosrl/newt/wgtester"
)

var wgServiceNative *wg.WireGuardService

func setupClientsNative(client *websocket.Client, host string) {

	if runtime.GOOS != "linux" {
		logger.Fatal("Tunnel management is only supported on Linux right now!")
		os.Exit(1)
	}

	// make sure we are sudo
	if os.Geteuid() != 0 {
		logger.Fatal("You must run this program as root to manage tunnels on Linux.")
		os.Exit(1)
	}

	// Create WireGuard service
	wgServiceNative, err = wg.NewWireGuardService(interfaceName, mtuInt, generateAndSaveKeyTo, host, id, client)
	if err != nil {
		logger.Fatal("Failed to create WireGuard service: %v", err)
	}

	wgTesterServer = wgtester.NewServer("0.0.0.0", wgServiceNative.Port, id) // TODO: maybe make this the same ip of the wg server?
	err := wgTesterServer.Start()
	if err != nil {
		logger.Error("Failed to start WireGuard tester server: %v", err)
	}

	client.OnTokenUpdate(func(token string) {
		wgServiceNative.SetToken(token)
	})
}

func closeWgServiceNative() {
	if wgServiceNative != nil {
		wgServiceNative.Close(!keepInterface)
		wgServiceNative = nil
	}
}

func clientsOnConnectNative() {
	if wgServiceNative != nil {
		wgServiceNative.LoadRemoteConfig()
	}
}

func clientsHandleNewtConnectionNative(publicKey, endpoint string) {
	if wgServiceNative != nil {
		wgServiceNative.StartHolepunch(publicKey, endpoint)
	}
}

func clientsAddProxyTargetNative(pm *proxy.ProxyManager, tunnelIp string) {
	if !ready {
		return
	}
	// add a udp proxy for localost and the wgService port
	// TODO: make sure this port is not used in a target
	if wgServiceNative != nil {
		pm.AddTarget("udp", tunnelIp, int(wgServiceNative.Port), fmt.Sprintf("127.0.0.1:%d", wgServiceNative.Port))
	}
}

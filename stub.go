//go:build !linux

package main

import (
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
)

func setupClientsNative(client *websocket.Client, host string) {
	_ = client
	_ = host
	// No-op for non-Linux systems
}

func closeWgServiceNative() {
	// No-op for non-Linux systems
}

func clientsOnConnectNative() {
	// No-op for non-Linux systems
}

func clientsHandleNewtConnectionNative(publicKey, endpoint string) {
	_ = publicKey
	_ = endpoint
	// No-op for non-Linux systems
}

func clientsAddProxyTargetNative(pm *proxy.ProxyManager, tunnelIp string) {
	_ = pm
	_ = tunnelIp
	// No-op for non-Linux systems
}

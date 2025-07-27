//go:build !linux

package main

import (
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
)

func setupClientsNative(client *websocket.Client, host string) {
	return // This function is not implemented for non-Linux systems.
}

func closeWgServiceNative() {
	// No-op for non-Linux systems
	return
}

func clientsOnConnectNative() {
	// No-op for non-Linux systems
	return
}

func clientsHandleNewtConnectionNative(publicKey, endpoint string) {
	// No-op for non-Linux systems
	return
}

func clientsAddProxyTargetNative(pm *proxy.ProxyManager, tunnelIp string) {
	// No-op for non-Linux systems
	return
}

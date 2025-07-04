//go:build !linux

package main

import (
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
)

func setupClients(client *websocket.Client) {
	return // This function is not implemented for non-Linux systems.
}

func closeClients() {
	// This function is not implemented for non-Linux systems.
	return
}

func clientsHandleNewtConnection(publicKey string) {
	// This function is not implemented for non-Linux systems.
	return
}

func clientsOnConnect() {
	// This function is not implemented for non-Linux systems.
	return
}

func clientsAddProxyTarget(pm *proxy.ProxyManager, tunnelIp string) {
	// This function is not implemented for non-Linux systems.
	return
}

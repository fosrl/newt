package newt

import (
	"fmt"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
)

// updateRemoteExitNodeSubnets replaces the set of active remote exit node
// subnets with the given list, updating WireGuard AllowedIPs and native
// routes to match.
func (n *Newt) updateRemoteExitNodeSubnets(subnets []string) {
	if n.config.UseNativeMainInterface && len(n.activeRemoteSubnets) > 0 {
		toRemove := make([]string, 0)
		newSet := make(map[string]bool, len(subnets))
		for _, s := range subnets {
			newSet[s] = true
		}
		for _, s := range n.activeRemoteSubnets {
			if !newSet[s] {
				toRemove = append(toRemove, s)
			}
		}
		if len(toRemove) > 0 {
			if err := network.RemoveRoutes(toRemove, n.config.NativeMainInterfaceName); err != nil {
				logger.Warn("Failed to remove old subnet routes: %v", err)
			}
		}
	}

	if n.dev != nil && n.wgData.PublicKey != "" {
		lines := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32",
			util.FixKey(n.wgData.PublicKey), n.wgData.ServerIP)
		for _, s := range subnets {
			lines += "\nallowed_ip=" + s
		}
		if err := n.dev.IpcSet(lines); err != nil {
			logger.Warn("Failed to update WireGuard AllowedIPs: %v", err)
		}
	}

	if n.config.UseNativeMainInterface && len(subnets) > 0 {
		existing := make(map[string]bool, len(n.activeRemoteSubnets))
		for _, s := range n.activeRemoteSubnets {
			existing[s] = true
		}
		toAdd := make([]string, 0)
		for _, s := range subnets {
			if !existing[s] {
				toAdd = append(toAdd, s)
			}
		}
		if len(toAdd) > 0 {
			if err := network.AddRoutes(toAdd, n.config.NativeMainInterfaceName); err != nil {
				logger.Warn("Failed to add new subnet routes: %v", err)
			}
		}
	}

	n.activeRemoteSubnets = append([]string{}, subnets...)
	logger.Info("Updated remote exit node subnets: %d total", len(subnets))
}

func (n *Newt) closeWgTunnel() {
	if n.pingStopChan != nil {
		close(n.pingStopChan)
		n.pingStopChan = nil
	}

	if n.browserGatewayStop != nil {
		n.browserGatewayStop()
		n.browserGatewayStop = nil
		n.browserGateway = nil
	}

	if n.pm != nil {
		n.pm.Stop()
		n.currentPM.Store(nil)
		n.pm = nil
	}

	if n.config.UseNativeMainInterface {
		toRemove := make([]string, 0, len(n.activeRemoteSubnets)+1)
		if n.wgData.ServerIP != "" {
			toRemove = append(toRemove, n.wgData.ServerIP+"/32")
		}
		toRemove = append(toRemove, n.activeRemoteSubnets...)
		if len(toRemove) > 0 {
			if err := network.RemoveRoutes(toRemove, n.config.NativeMainInterfaceName); err != nil {
				logger.Warn("Failed to remove native main tunnel routes: %v", err)
			}
		}
		n.activeRemoteSubnets = nil
	}

	if n.dev != nil {
		n.dev.Close()
		n.dev = nil
	}

	if n.tnet != nil {
		n.tnet = nil
	}
	if n.tun != nil {
		n.tun = nil
	}
}

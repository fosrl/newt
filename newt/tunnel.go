package newt

import (
	"fmt"
	"os"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
	"github.com/fosrl/newt/util"
)

// updateRemoteExitNodeSubnets replaces the set of active remote exit node
// subnets with the given list, updating WireGuard AllowedIPs and native
// routes to match.
func (n *Newt) updateRemoteExitNodeSubnets(subnets []string) error {
	n.lifecycleMu.Lock()
	defer n.lifecycleMu.Unlock()
	if n.stopping.Load() {
		return fmt.Errorf("newt is shutting down")
	}
	return n.updateRemoteExitNodeSubnetsLocked(subnets)
}

func (n *Newt) updateRemoteExitNodeSubnetsLocked(subnets []string) error {
	if n.kernelMain != nil {
		allowed, err := mainAllowedIPs(n.wgData.ServerIP, subnets)
		if err == nil {
			err = n.kernelMain.SetAllowedIPs(allowed)
		}
		if err != nil {
			logger.Error("Failed to update kernel main tunnel subnets: %v", err)
			// An OS rollback can itself fail. Rebuild from the next complete
			// server configuration instead of continuing with partial routes.
			n.closeWgTunnelLocked()
			n.requestKernelReconnect()
			return err
		}
		n.activeRemoteSubnets = append([]string(nil), subnets...)
		return nil
	}
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
	return nil
}

func (n *Newt) closeWgTunnel() {
	n.lifecycleMu.Lock()
	defer n.lifecycleMu.Unlock()
	n.closeWgTunnelLocked()
}

func (n *Newt) closeWgTunnelLocked() {
	if n.mainPingCancel != nil {
		n.mainPingCancel()
		n.mainPingCancel = nil
	}
	if n.pingWithRetryStopChan != nil {
		close(n.pingWithRetryStopChan)
		n.pingWithRetryStopChan = nil
	}
	if n.pingStopChan != nil {
		close(n.pingStopChan)
		n.pingStopChan = nil
	}
	// Closing the userspace device interrupts netstack reads before waiting
	// for probes. Host probes are canceled through mainPingCancel above.
	if n.dev != nil {
		n.dev.Close()
		n.dev = nil
	} else if n.tun != nil {
		n.tun.Close()
	}
	n.pingWorkers.Wait()
	if n.config.HealthFile != "" {
		if err := os.Remove(n.config.HealthFile); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove health file: %v", err)
		}
	}
	if n.mainUAPI != nil {
		n.mainUAPI.Close()
		n.mainUAPI = nil
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

	if n.kernelMain != nil {
		if err := n.kernelMain.Close(); err != nil {
			logger.Error("Failed to clean up kernel main tunnel: %v", err)
		}
		n.kernelMain = nil
	}

	if n.tnet != nil {
		n.tnet = nil
	}
	if n.tun != nil {
		n.tun = nil
	}
	n.setDownstreamTNetstack(nil)
	n.activeRemoteSubnets = nil
	n.connected = false
}

func (n *Newt) requestKernelReconnect() {
	if !n.config.UseKernelMainInterface || n.client == nil || n.stopping.Load() {
		return
	}
	if n.stopFunc != nil {
		n.stopFunc()
	}
	chainID := generateChainId()
	n.pendingPingChainId = chainID
	n.stopFunc = n.client.SendMessageInterval("newt/ping/request", map[string]interface{}{
		"noCloud": n.config.NoCloud,
		"chainId": chainID,
	}, 3*time.Second)
}

// schedulePingRecovery keeps registration state under lifecycleMu without
// making a ping worker wait for that mutex: teardown holds it while joining
// those workers. A stopped/replaced probe cannot reconnect the next tunnel.
func (n *Newt) schedulePingRecovery(stop <-chan struct{}, tunnelID string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.lifecycleMu.Lock()
		defer n.lifecycleMu.Unlock()
		if n.stopping.Load() || n.client == nil || n.wgData.PublicKey != tunnelID {
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		if n.stopFunc != nil {
			n.stopFunc()
		}
		chainID := generateChainId()
		n.pendingPingChainId = chainID
		n.stopFunc = n.client.SendMessageInterval("newt/ping/request", map[string]interface{}{
			"noCloud": n.config.NoCloud,
			"chainId": chainID,
		}, 3*time.Second)
		// This compatibility registration has no wg/connect response and must
		// not supersede the pending real registration chain.
		if err := n.client.SendMessage("newt/wg/register", map[string]interface{}{
			"publicKey":           n.publicKey.String(),
			"backwardsCompatible": true,
			"chainId":             generateChainId(),
		}); err != nil {
			logger.Error("Failed to send registration message: %v", err)
		}
		if n.config.HealthFile != "" {
			if err := os.Remove(n.config.HealthFile); err != nil && !os.IsNotExist(err) {
				logger.Error("Failed to remove health file: %v", err)
			}
		}
	}()
	return done
}

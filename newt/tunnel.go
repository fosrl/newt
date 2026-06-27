package newt

import (
	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/network"
)

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
			if err := network.RemoveRoutes(toRemove); err != nil {
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

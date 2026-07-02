package newt

import (
	wgclients "github.com/fosrl/newt/clients"
	"github.com/fosrl/newt/healthcheck"
)

type BrowserGatewayTarget struct {
	ID              int    `json:"id"`
	Type            string `json:"type"`
	Destination     string `json:"destination"`
	DestinationPort int    `json:"destinationPort"`
	AuthToken       string `json:"authToken"`
}

type WgData struct {
	Endpoint              string                 `json:"endpoint"`
	RelayPort             uint16                 `json:"relayPort"`
	PublicKey             string                 `json:"publicKey"`
	ServerIP              string                 `json:"serverIP"`
	TunnelIP              string                 `json:"tunnelIP"`
	Targets               TargetsByType          `json:"targets"`
	HealthCheckTargets    []healthcheck.Config   `json:"healthCheckTargets"`
	BrowserGatewayTargets []BrowserGatewayTarget `json:"browserGatewayTargets"`
	RemoteExitNodeSubnets []string               `json:"remoteExitNodeSubnets"`
	ChainId               string                 `json:"chainId"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

type ExitNodeData struct {
	ExitNodes []ExitNode `json:"exitNodes"`
	ChainId   string     `json:"chainId"`
}

type ExitNode struct {
	ID                     int     `json:"exitNodeId"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	Weight                 float64 `json:"weight"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

type ExitNodePingResult struct {
	ExitNodeID             int     `json:"exitNodeId"`
	LatencyMs              int64   `json:"latencyMs"`
	Weight                 float64 `json:"weight"`
	Error                  string  `json:"error,omitempty"`
	Name                   string  `json:"exitNodeName"`
	Endpoint               string  `json:"endpoint"`
	WasPreviouslyConnected bool    `json:"wasPreviouslyConnected"`
}

type BlueprintResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// Define the sync data structure
type SyncData struct {
	Targets               TargetsByType          `json:"proxyTargets"`
	HealthCheckTargets    []healthcheck.Config   `json:"healthCheckTargets"`
	RemoteExitNodeSubnets []string               `json:"remoteExitNodeSubnets"`
	Peers                 []wgclients.Peer       `json:"peers"`
	ClientTargets         []wgclients.Target     `json:"clientTargets"`
	BrowserGatewayTargets []BrowserGatewayTarget `json:"browserGatewayTargets"`
}

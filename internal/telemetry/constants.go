package telemetry

// Protocol labels (low-cardinality)
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Reconnect reason bins (fixed, low-cardinality)
const (
	ReasonServerRequest  = "server_request"
	ReasonTimeout        = "timeout"
	ReasonPeerClose      = "peer_close"
	ReasonNetworkChange  = "network_change"
	ReasonAuthError      = "auth_error"
	ReasonHandshakeError = "handshake_error"
	ReasonConfigChange   = "config_change"
	ReasonError          = "error"
)

package telemetry

import "testing"

func TestAllowedConstants(t *testing.T) {
	allowedReasons := map[string]struct{}{
		ReasonServerRequest:  {},
		ReasonTimeout:        {},
		ReasonPeerClose:      {},
		ReasonNetworkChange:  {},
		ReasonAuthError:      {},
		ReasonHandshakeError: {},
		ReasonConfigChange:   {},
		ReasonError:          {},
	}
	for k := range allowedReasons {
		if k == "" {
			t.Fatalf("empty reason constant")
		}
	}

	allowedProtocols := map[string]struct{}{
		ProtocolTCP: {},
		ProtocolUDP: {},
	}
	for k := range allowedProtocols {
		if k == "" {
			t.Fatalf("empty protocol constant")
		}
	}
}


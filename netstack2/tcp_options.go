package netstack2

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// configureTCP sets the TCP options newt uses on a netstack: SACK on, and
// gVisor's RACK loss detection off, which also turns off its tail loss
// probes.
//
// gVisor turns RACK on by default. In the gVisor newt uses, after a burst of
// losses that takes out everything in flight, RACK recovers only a few
// segments per retransmission timeout, so the download crawls for seconds or
// minutes (tailscale/tailscale#21946). Without RACK, gVisor recovers with
// SACK (RFC 6675), as Tailscale's netstack does since
// tailscale/tailscale#22092. RACK can go back on once newt's gVisor has
// google/gvisor#16081.
func configureTCP(s *stack.Stack) error {
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	recovery := tcpip.TCPRecovery(0)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		return fmt.Errorf("could not disable TCP RACK: %v", err)
	}
	return nil
}

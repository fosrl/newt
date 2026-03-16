package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"github.com/fosrl/newt/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
)

// tunnelEntry holds per-tunnel attributes and (optional) async counters.
type tunnelEntry struct {
	attrInTCP  attribute.Set
	attrOutTCP attribute.Set
	attrInUDP  attribute.Set
	attrOutUDP attribute.Set

	bytesInTCP  atomic.Uint64
	bytesOutTCP atomic.Uint64
	bytesInUDP  atomic.Uint64
	bytesOutUDP atomic.Uint64

	activeTCP atomic.Int64
	activeUDP atomic.Int64
}

// flush sends accumulated byte counters to telemetry and resets them.
// Returns true if any bytes were flushed.
func (e *tunnelEntry) flush() bool {
	inTCP := e.bytesInTCP.Swap(0)
	outTCP := e.bytesOutTCP.Swap(0)
	inUDP := e.bytesInUDP.Swap(0)
	outUDP := e.bytesOutUDP.Swap(0)

	flushed := false
	if inTCP > 0 {
		telemetry.AddTunnelBytesSet(context.Background(), int64(inTCP), e.attrInTCP)
		flushed = true
	}
	if outTCP > 0 {
		telemetry.AddTunnelBytesSet(context.Background(), int64(outTCP), e.attrOutTCP)
		flushed = true
	}
	if inUDP > 0 {
		telemetry.AddTunnelBytesSet(context.Background(), int64(inUDP), e.attrInUDP)
		flushed = true
	}
	if outUDP > 0 {
		telemetry.AddTunnelBytesSet(context.Background(), int64(outUDP), e.attrOutUDP)
		flushed = true
	}
	return flushed
}

// buildAttrs initializes the attribute sets for a tunnel entry.
func (e *tunnelEntry) buildAttrs(tunnelID string) {
	site := telemetry.SiteLabelKVs()
	build := func(base []attribute.KeyValue) attribute.Set {
		if telemetry.ShouldIncludeTunnelID() {
			base = append([]attribute.KeyValue{attribute.String("tunnel_id", tunnelID)}, base...)
		}
		base = append(site, base...)
		return attribute.NewSet(base...)
	}
	e.attrInTCP = build([]attribute.KeyValue{
		attribute.String("direction", "ingress"),
		attribute.String("protocol", "tcp"),
	})
	e.attrOutTCP = build([]attribute.KeyValue{
		attribute.String("direction", "egress"),
		attribute.String("protocol", "tcp"),
	})
	e.attrInUDP = build([]attribute.KeyValue{
		attribute.String("direction", "ingress"),
		attribute.String("protocol", "udp"),
	})
	e.attrOutUDP = build([]attribute.KeyValue{
		attribute.String("direction", "egress"),
		attribute.String("protocol", "udp"),
	})
}

// countingWriter wraps an io.Writer and adds bytes to telemetry counters.
type countingWriter struct {
	ctx        context.Context
	w          io.Writer
	set        attribute.Set
	entry      *tunnelEntry
	asyncBytes bool
	out        bool   // false=in, true=out
	proto      string // "tcp" or "udp"
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		if cw.asyncBytes && cw.entry != nil {
			switch cw.proto {
			case "tcp":
				if cw.out {
					cw.entry.bytesOutTCP.Add(uint64(n))
				} else {
					cw.entry.bytesInTCP.Add(uint64(n))
				}
			case "udp":
				if cw.out {
					cw.entry.bytesOutUDP.Add(uint64(n))
				} else {
					cw.entry.bytesInUDP.Add(uint64(n))
				}
			}
		} else {
			telemetry.AddTunnelBytesSet(cw.ctx, int64(n), cw.set)
		}
	}
	return n, err
}

// classifyProxyError returns a low-cardinality error category for telemetry.
func classifyProxyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, net.ErrClosed) {
		return "closed"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "reset"):
		return "reset"
	default:
		return "io_error"
	}
}

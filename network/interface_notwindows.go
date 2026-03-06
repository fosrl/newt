//go:build !windows

package network

import (
	"fmt"
	"net/netip"
)

func configureWindows(interfaceName string, prefix netip.Prefix) error {
	return fmt.Errorf("configureWindows called on non-Windows platform")
}

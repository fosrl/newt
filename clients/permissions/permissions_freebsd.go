//go:build freebsd

package permissions

import (
	"fmt"
	"os"

	"github.com/fosrl/newt/logger"
)

const (
	// TUN device on FreeBSD
	tunDevice = "/dev/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000
)

// ifReq is the structure for TUN interface configuration
type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte // padding to match kernel structure
}

// CheckNativeInterfacePermissions checks if the process has sufficient
// permissions to create a native TUN interface on FreeBSD.
// This requires root privileges (UID 0).
func CheckNativeInterfacePermissions() error {
	logger.Debug("Checking native interface permissions on FreeBSD")

	// Check if running as root
	if os.Geteuid() == 0 {
		logger.Debug("Running as root, sufficient permissions for native TUN interface")
		return nil
	}

	// On FreeBSD, only root can create TUN interfaces
	// Try to open the TUN device to verify
	return tryOpenTunDevice()
}

// tryOpenTunDevice attempts to open the TUN device to verify permissions.
// On FreeBSD, /dev/tun is a cloning device that creates a new interface
// when opened.
func tryOpenTunDevice() error {
	// Try opening /dev/tun (cloning device)
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %v (need root privileges)", tunDevice, err)
	}
	defer f.Close()

	logger.Debug("Successfully opened TUN device, sufficient permissions for native TUN interface")
	return nil
}

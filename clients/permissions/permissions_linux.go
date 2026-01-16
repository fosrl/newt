//go:build linux && !android

package permissions

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/fosrl/newt/logger"
	"golang.org/x/sys/unix"
)

const (
	// TUN device constants
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

// ifReq is the structure for TUNSETIFF ioctl
type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_     [22]byte // padding to match kernel structure
}

// CheckNativeInterfacePermissions checks if the process has sufficient
// permissions to create a native TUN interface on Linux.
// This requires either root privileges (UID 0) or CAP_NET_ADMIN capability.
func CheckNativeInterfacePermissions() error {
	logger.Debug("Checking native interface permissions on Linux")

	// Check if running as root
	if os.Geteuid() == 0 {
		logger.Debug("Running as root, sufficient permissions for native TUN interface")
		return nil
	}

	// Check for CAP_NET_ADMIN capability
	caps := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0, // 0 means current process
	}

	var data [2]unix.CapUserData
	if err := unix.Capget(&caps, &data[0]); err != nil {
		logger.Debug("Failed to get capabilities: %v, will try creating test TUN", err)
	} else {
		// CAP_NET_ADMIN is capability bit 12
		const CAP_NET_ADMIN = 12
		if data[0].Effective&(1<<CAP_NET_ADMIN) != 0 {
			logger.Debug("Process has CAP_NET_ADMIN capability, sufficient permissions for native TUN interface")
			return nil
		}
		logger.Debug("Process does not have CAP_NET_ADMIN capability in effective set")
	}

	// Actually try to create a TUN interface to verify permissions
	// This is the most reliable check as it tests the actual operation
	return tryCreateTestTun()
}

// tryCreateTestTun attempts to create a temporary TUN interface to verify
// we have the necessary permissions. This tests the actual ioctl call that
// will be used when creating the real interface.
func tryCreateTestTun() error {
	f, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open %s: %v (need root or CAP_NET_ADMIN capability)", tunDevice, err)
	}
	defer f.Close()

	// Try to create a TUN interface with a test name
	// Using a random-ish name to avoid conflicts
	var req ifReq
	copy(req.Name[:], "tuntest0")
	req.Flags = iffTun | iffNoPi

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(tunSetIff),
		uintptr(unsafe.Pointer(&req)),
	)

	if errno != 0 {
		return fmt.Errorf("cannot create TUN interface (ioctl TUNSETIFF failed): %v (need root or CAP_NET_ADMIN capability)", errno)
	}

	// Success - the interface will be automatically destroyed when we close the fd
	logger.Debug("Successfully created test TUN interface, sufficient permissions for native TUN interface")
	return nil
}

//go:build windows

package device

import (
	"errors"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func CreateTUNFromFD(tunFd uint32, mtuInt int) (tun.Device, error) {
	return nil, errors.New("CreateTUNFromFile not supported on Windows")
}

func UapiOpen(interfaceName string) (*os.File, error) {
	return nil, nil
}

func UapiListen(interfaceName string, fileUAPI *os.File) (net.Listener, error) {
	// On Windows, UAPIListen only takes one parameter
	return ipc.UAPIListen(interfaceName)
}

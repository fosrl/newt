//go:build !windows

package network

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	return nil
}

func WindowsRemoveRoute(destination string) error {
	return nil
}

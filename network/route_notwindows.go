//go:build !windows

package network

func WindowsAddRoute(destination string, gateway string, interfaceName string) error {
	return nil
}

func WindowsRemoveRoute(destination string, interfaceName string) error {
	return nil
}

func WindowsAddBypassRoute(destIP string) error {
	return nil
}

func WindowsRemoveBypassRoute(destIP string) error {
	return nil
}

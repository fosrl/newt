//go:build !windows

package main

import (
	"fmt"
)

// Service management functions are not available on non-Windows platforms
func installService() error {
	return fmt.Errorf("service management is only available on Windows")
}

func removeService() error {
	return fmt.Errorf("service management is only available on Windows")
}

func startService(args []string) error {
	_ = args // unused on Unix platforms
	return fmt.Errorf("service management is only available on Windows")
}

func stopService() error {
	return fmt.Errorf("service management is only available on Windows")
}

func getServiceStatus() (string, error) {
	return "", fmt.Errorf("service management is only available on Windows")
}

func debugService(args []string) error {
	_ = args // unused on Unix platforms
	return fmt.Errorf("debug service is only available on Windows")
}

func isWindowsService() bool {
	return false
}

func runService(name string, isDebug bool, args []string) {
	// No-op on non-Windows platforms
}

func setupWindowsEventLog() {
	// No-op on non-Windows platforms
}

func watchLogFile(end bool) error {
	return fmt.Errorf("watching log file is only available on Windows")
}

func showServiceConfig() {
	fmt.Println("Service configuration is only available on Windows")
}

// handleServiceCommand returns false on non-Windows platforms
func handleServiceCommand() bool {
	return false
}

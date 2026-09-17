//go:build !linux

package kernelwg

import "errors"

// Open is unsupported outside Linux; no userspace fallback is implicit.
func Open(Config) (*Device, error) {
	return nil, errors.New("kernel WireGuard main tunnels are supported only on Linux")
}

//go:build windows

package browsergateway

import (
	"context"
	"errors"

	"github.com/coder/websocket"
	"github.com/fosrl/newt/nativessh"
)

// serveNativeSSHSession is not supported on Windows.
func serveNativeSSHSession(_ context.Context, _ *websocket.Conn, _ string, _ *nativessh.CredentialStore) error {
	return errors.New("native SSH is not supported on Windows")
}

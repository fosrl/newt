//go:build !windows

package browsergateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/coder/websocket"
	"github.com/fosrl/newt/pkg/nativessh"
)

// serveNativeSSHSession handles a WebSocket SSH session by authenticating the
// user against the host OS (authorized_keys then PAM password) and then
// spawning a PTY+shell running as that user.
//
// The auth frame from the browser must be a JSON sshClientMsg with type="auth"
// carrying the same password/privateKey fields used by the proxy SSH path.
// The target username is passed in from the HTTP layer (query param).
func serveNativeSSHSession(ctx context.Context, ws *websocket.Conn, username string, creds *nativessh.CredentialStore) error {
	// Read the auth frame.
	_, authBytes, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("read auth message: %w", err)
	}
	var authMsg sshClientMsg
	if err := json.Unmarshal(authBytes, &authMsg); err != nil || authMsg.Type != "auth" {
		return fmt.Errorf("expected auth message, got: %s", authBytes)
	}

	// Authenticate using host authorized_keys or PAM password.
	if err := nativessh.AuthenticateWithCertificate(creds, username, authMsg.Password, authMsg.PrivateKey, authMsg.Certificate); err != nil {
		sendSSHError(ctx, ws, "Authentication failed")
		return fmt.Errorf("auth for user %q: %w", username, err)
	}

	log.Printf("SSH native: spawning shell as user %q", username)

	sess, err := nativessh.NewPTYSessionAs(username)
	if err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("Failed to spawn shell: %v", err))
		return fmt.Errorf("pty session as %q: %w", username, err)
	}
	defer sess.Close()

	// Cancel context to unblock the WebSocket read loop when the shell exits.
	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()

	// Pump PTY output → WebSocket.
	go func() {
		defer cancelSess()
		buf := make([]byte, 4096)
		for {
			n, readErr := sess.Read(buf)
			if n > 0 {
				msg := sshServerMsg{Type: "data", Data: string(buf[:n])}
				b, _ := json.Marshal(msg)
				if writeErr := ws.Write(sessCtx, websocket.MessageText, b); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Pump WebSocket input → PTY stdin / resize.
	for {
		_, msgBytes, readErr := ws.Read(sessCtx)
		if readErr != nil {
			break
		}
		var msg sshClientMsg
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "data":
			if _, writeErr := sess.Write([]byte(msg.Data)); writeErr != nil {
				return fmt.Errorf("write pty: %w", writeErr)
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = sess.Resize(uint16(msg.Cols), uint16(msg.Rows))
			}
		}
	}

	return nil
}

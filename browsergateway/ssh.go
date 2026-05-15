package browsergateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
)

// sshClientMsg is a JSON message sent from the browser to the proxy.
type sshClientMsg struct {
	// type: "auth" | "data" | "resize"
	Type       string `json:"type"`
	Password   string `json:"password,omitempty"`   // used when type="auth"
	PrivateKey string `json:"privateKey,omitempty"` // used when type="auth"
	Data       string `json:"data,omitempty"`       // used when type="data"
	Cols       uint32 `json:"cols,omitempty"`       // used when type="resize"
	Rows       uint32 `json:"rows,omitempty"`       // used when type="resize"
}

// sshServerMsg is a JSON message sent from the proxy back to the browser.
type sshServerMsg struct {
	// type: "data" | "error"
	Type  string `json:"type"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// HandleSSH is an http.HandlerFunc for SSH-over-WebSocket connections.
func (g *Gateway) HandleSSH(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.URL.Query().Get("authToken")

	// In proxy mode we also need host + username from query params.
	var target, username string
	if g.nativeSSH == nil {
		host := r.URL.Query().Get("host")
		port := r.URL.Query().Get("port")
		username = r.URL.Query().Get("username")
		if host == "" || username == "" {
			http.Error(w, "missing host or username", http.StatusBadRequest)
			return
		}
		if port == "" {
			port = "22"
		}
		sshPort, _ := strconv.Atoi(port)
		if !g.isAllowed("ssh", host, sshPort, token) {
			http.Error(w, "destination not allowed or auth token mismatch", http.StatusForbidden)
			return
		}
		target = net.JoinHostPort(host, port)
	} else {
		// Native SSH mode: validate against the global gateway token.
		if subtle.ConstantTimeCompare([]byte(token), []byte(g.authToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       []string{"ssh"},
	})
	if err != nil {
		log.Printf("SSH websocket upgrade failed: %v", err)
		return
	}
	ws.SetReadLimit(-1)
	defer ws.CloseNow() //nolint:errcheck

	if g.nativeSSH != nil {
		if err := serveNativeSSHSession(ctx, ws, *g.nativeSSH); err != nil {
			log.Printf("SSH native session error: %v", err)
		}
	} else {
		if err := serveSSHSession(ctx, ws, target, username, g.authToken); err != nil {
			log.Printf("SSH session error: %v", err)
		}
	}
}

func serveSSHSession(ctx context.Context, ws *websocket.Conn, target, username, _ string) error {
	// -- Wait for the auth message from the client to get the password --
	_, authBytes, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("read auth message: %w", err)
	}
	var authMsg sshClientMsg
	if err := json.Unmarshal(authBytes, &authMsg); err != nil || authMsg.Type != "auth" {
		return fmt.Errorf("expected auth message, got: %s", authBytes)
	}
	password := authMsg.Password
	privateKey := authMsg.PrivateKey

	// Build the list of auth methods. Private key takes priority when provided.
	var authMethods []ssh.AuthMethod
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			sendSSHError(ctx, ws, fmt.Sprintf("Failed to parse private key: %v", err))
			return fmt.Errorf("parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if len(authMethods) == 0 {
		sendSSHError(ctx, ws, "No authentication credentials provided")
		return fmt.Errorf("no auth credentials")
	}
	log.Printf("SSH: connecting to %s as %s", target, username)
	sshCfg := &ssh.ClientConfig{
		User: username,
		Auth: authMethods,
		// HostKeyCallback is intentionally InsecureIgnoreHostKey for this dev
		// proxy. In production, verify against a known-hosts store.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         15 * time.Second,
	}

	sshClient, err := ssh.Dial("tcp", target, sshCfg)
	if err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("SSH dial failed: %v", err))
		return fmt.Errorf("ssh dial %s: %w", target, err)
	}
	defer sshClient.Close()

	// -- Open an interactive session --
	sess, err := sshClient.NewSession()
	if err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("Failed to open SSH session: %v", err))
		return fmt.Errorf("ssh new session: %w", err)
	}
	defer sess.Close()

	// Request a PTY.
	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}); err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("Failed to request PTY: %v", err))
		return fmt.Errorf("ssh request pty: %w", err)
	}

	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("ssh stdin pipe: %w", err)
	}
	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ssh stdout pipe: %w", err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return fmt.Errorf("ssh stderr pipe: %w", err)
	}

	if err := sess.Shell(); err != nil {
		sendSSHError(ctx, ws, fmt.Sprintf("Failed to start shell: %v", err))
		return fmt.Errorf("ssh shell: %w", err)
	}

	log.Printf("SSH: session established with %s", target)

	// -- Pump SSH stdout/stderr → WebSocket --
	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := stdoutPipe.Read(buf)
			if n > 0 {
				msg := sshServerMsg{Type: "data", Data: string(buf[:n])}
				b, _ := json.Marshal(msg)
				if writeErr := ws.Write(sessCtx, websocket.MessageText, b); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				cancelSess()
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := stderrPipe.Read(buf)
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

	// -- Pump WebSocket input → SSH stdin / resize --
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
			if _, err := stdinPipe.Write([]byte(msg.Data)); err != nil {
				return fmt.Errorf("write ssh stdin: %w", err)
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = sess.WindowChange(int(msg.Rows), int(msg.Cols))
			}
		}
	}

	return nil
}

// sendSSHError sends an error message to the browser and logs it.
func sendSSHError(ctx context.Context, ws *websocket.Conn, msg string) {
	log.Printf("SSH error: %s", msg)
	b, _ := json.Marshal(sshServerMsg{Type: "error", Error: msg})
	_ = ws.Write(ctx, websocket.MessageText, b)
}

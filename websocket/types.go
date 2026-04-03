package websocket

type Config struct {
	ID            string `json:"id"`
	Secret        string `json:"secret"`
	Endpoint      string `json:"endpoint"`
	TlsClientCert string `json:"tlsClientCert"`
}

type TokenResponse struct {
	Data struct {
		Token         string `json:"token"`
		ServerVersion string `json:"serverVersion"`
	} `json:"data"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type WSMessage struct {
	Type          string      `json:"type"`
	Data          interface{} `json:"data"`
	ConfigVersion int64       `json:"configVersion,omitempty"`
}

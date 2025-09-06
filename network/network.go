package network

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	timeout = time.Second * 10
)

// Server stores data relating to the server
type Server struct {
	Hostname string
	Addr     net.IP
	Port     uint16
}

// PeerNet stores data about a peer's endpoint
type PeerNet struct {
	Resolved bool
	IP       net.IP
	Port     uint16
	NewtID   string
}

// GetClientIP gets the source IP address for a destination.
func GetClientIP(dstIP net.IP) net.IP {
	routes, err := netlink.RouteGet(dstIP)
	if err != nil || len(routes) == 0 {
		log.Fatalln("Error getting route:", err)
	}
	return routes[0].Src
}

// HostToAddr resolves a hostname, preferring IPv4.
func HostToAddr(hostStr string) net.IP {
	ips, err := net.LookupIP(hostStr)
	if err != nil {
		log.Fatalf("Error looking up host %s: %v", hostStr, err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	if len(ips) > 0 {
		return ips[0]
	}
	log.Fatalf("No IP address found for host: %s", hostStr)
	return nil
}

// SetupConn creates a standard UDP connection for the appropriate IP family.
// The BPF and raw socket logic has been removed for compatibility.
func SetupConn(client *PeerNet) net.PacketConn {
	var networkType string
	var localAddr string

	if client.IP.To4() != nil {
		networkType = "udp4"
		localAddr = fmt.Sprintf("%s:%d", client.IP.String(), client.Port)
	} else if client.IP.To16() != nil {
		networkType = "udp6"
		localAddr = fmt.Sprintf("[%s]:%d", client.IP.String(), client.Port)
	} else {
		log.Fatalln("Client IP is not a valid IPv4 or IPv6 address")
	}

	conn, err := net.ListenPacket(networkType, localAddr)
	if err != nil {
		log.Fatalf("Error creating packetConn for %s: %v", localAddr, err)
	}
	return conn
}

// SendDataPacket sends a JSON payload to the Server using a standard UDP socket.
func SendDataPacket(data interface{}, conn net.PacketConn, server *Server, client *PeerNet) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	destAddr := &net.UDPAddr{
		IP:   server.Addr,
		Port: int(server.Port),
	}

	_, err = conn.WriteTo(jsonData, destAddr)
	return err
}

// RecvDataPacket receives a JSON packet from the server.
func RecvDataPacket(conn net.PacketConn) ([]byte, error) {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

// ParseResponse takes a response packet and parses it into an IP and port.
func ParseResponse(response []byte) (net.IP, uint16) {
	if len(response) < 6 {
		return nil, 0
	}
	ip := net.IP(response[:4])
	port := binary.BigEndian.Uint16(response[4:6])
	return ip, port
}
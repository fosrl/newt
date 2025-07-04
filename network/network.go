package network

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

const (
	udpProtocol = 17
	// EmptyUDPSize is the size of an empty UDP packet
	EmptyUDPSize = 28
	timeout      = time.Second * 10
)

// Server stores data relating to the server
type Server struct {
	Hostname string
	Addr     *net.IPAddr
	Port     uint16
}

// PeerNet stores data about a peer's endpoint
type PeerNet struct {
	Resolved bool
	IP       net.IP
	Port     uint16
	NewtID   string
}

// GetClientIP gets source ip address that will be used when sending data to dstIP
func GetClientIP(dstIP net.IP) net.IP {
	routes, err := netlink.RouteGet(dstIP)
	if err != nil {
		log.Fatalln("Error getting route:", err)
	}
	return routes[0].Src
}

// HostToAddr resolves a hostname, whether DNS or IP to a valid net.IPAddr
func HostToAddr(hostStr string) *net.IPAddr {
	remoteAddrs, err := net.LookupHost(hostStr)
	if err != nil {
		log.Fatalln("Error parsing remote address:", err)
	}

	for _, addrStr := range remoteAddrs {
		if remoteAddr, err := net.ResolveIPAddr("ip4", addrStr); err == nil {
			return remoteAddr
		}
	}
	return nil
}

// SetupRawConn creates an ipv4 and udp only RawConn and applies packet filtering
func SetupRawConn(server *Server, client *PeerNet) *ipv4.RawConn {
	packetConn, err := net.ListenPacket("ip4:udp", client.IP.String())
	if err != nil {
		log.Fatalln("Error creating packetConn:", err)
	}

	rawConn, err := ipv4.NewRawConn(packetConn)
	if err != nil {
		log.Fatalln("Error creating rawConn:", err)
	}

	ApplyBPF(rawConn, server, client)

	return rawConn
}

// ApplyBPF constructs a BPF program and applies it to the RawConn
func ApplyBPF(rawConn *ipv4.RawConn, server *Server, client *PeerNet) {
	const ipv4HeaderLen = 20
	const srcIPOffset = 12
	const srcPortOffset = ipv4HeaderLen + 0
	const dstPortOffset = ipv4HeaderLen + 2

	ipArr := []byte(server.Addr.IP.To4())
	ipInt := uint32(ipArr[0])<<(3*8) + uint32(ipArr[1])<<(2*8) + uint32(ipArr[2])<<8 + uint32(ipArr[3])

	bpfRaw, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: srcIPOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipInt, SkipFalse: 5, SkipTrue: 0},

		bpf.LoadAbsolute{Off: srcPortOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(server.Port), SkipFalse: 3, SkipTrue: 0},

		bpf.LoadAbsolute{Off: dstPortOffset, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(client.Port), SkipFalse: 1, SkipTrue: 0},

		bpf.RetConstant{Val: 1<<(8*4) - 1},
		bpf.RetConstant{Val: 0},
	})

	if err != nil {
		log.Fatalln("Error assembling BPF:", err)
	}

	err = rawConn.SetBPF(bpfRaw)
	if err != nil {
		log.Fatalln("Error setting BPF:", err)
	}
}

// MakePacket constructs a request packet to send to the server
func MakePacket(payload []byte, server *Server, client *PeerNet) []byte {
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ipHeader := layers.IPv4{
		SrcIP:    client.IP,
		DstIP:    server.Addr.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udpHeader := layers.UDP{
		SrcPort: layers.UDPPort(client.Port),
		DstPort: layers.UDPPort(server.Port),
	}

	payloadLayer := gopacket.Payload(payload)

	udpHeader.SetNetworkLayerForChecksum(&ipHeader)

	gopacket.SerializeLayers(buf, opts, &ipHeader, &udpHeader, &payloadLayer)

	return buf.Bytes()
}

// SendPacket sends packet to the Server
func SendPacket(packet []byte, conn *ipv4.RawConn, server *Server, client *PeerNet) error {
	fullPacket := MakePacket(packet, server, client)
	_, err := conn.WriteToIP(fullPacket, server.Addr)
	return err
}

// SendDataPacket sends a JSON payload to the Server
func SendDataPacket(data interface{}, conn *ipv4.RawConn, server *Server, client *PeerNet) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	return SendPacket(jsonData, conn, server, client)
}

// RecvPacket receives a UDP packet from server
func RecvPacket(conn *ipv4.RawConn, server *Server, client *PeerNet) ([]byte, int, error) {
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, 0, err
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, n, err
	}
	return response, n, nil
}

// RecvDataPacket receives and unmarshals a JSON packet from server
func RecvDataPacket(conn *ipv4.RawConn, server *Server, client *PeerNet) ([]byte, error) {
	response, n, err := RecvPacket(conn, server, client)
	if err != nil {
		return nil, err
	}

	// Extract payload from UDP packet
	payload := response[EmptyUDPSize:n]
	return payload, nil
}

// ParseResponse takes a response packet and parses it into an IP and port
func ParseResponse(response []byte) (net.IP, uint16) {
	ip := net.IP(response[:4])
	port := binary.BigEndian.Uint16(response[4:6])
	return ip, port
}

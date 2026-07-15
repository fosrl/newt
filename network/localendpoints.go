package network

import (
	"net"
	"regexp"
	"sort"
	"strconv"

	"github.com/fosrl/newt/logger"
)

// Interface name patterns used to rank candidate local endpoints. Interfaces
// matching physicalInterfacePatterns are tried first, interfaces matching
// virtualInterfacePatterns (container/VPN/hypervisor bridges and the like)
// are tried last, and everything else falls in between.
var (
	physicalInterfacePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^eth\d+$`),
		regexp.MustCompile(`(?i)^en\d+$`),
		regexp.MustCompile(`(?i)^eno\d+$`),
		regexp.MustCompile(`(?i)^ens\d+$`),
		regexp.MustCompile(`(?i)^enp\d+s\d+`),
		regexp.MustCompile(`(?i)^wlan\d*$`),
		regexp.MustCompile(`(?i)^wlp\d+s\d+`),
		regexp.MustCompile(`(?i)^wl\d+$`),
		regexp.MustCompile(`(?i)ethernet`),
		regexp.MustCompile(`(?i)wi-?fi`),
		regexp.MustCompile(`(?i)wireless`),
	}

	virtualInterfacePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)docker`),
		regexp.MustCompile(`(?i)podman`),
		regexp.MustCompile(`(?i)^veth`),
		regexp.MustCompile(`(?i)^virbr`),
		regexp.MustCompile(`(?i)vmnet`),
		regexp.MustCompile(`(?i)vboxnet`),
		regexp.MustCompile(`(?i)virtualbox`),
		regexp.MustCompile(`(?i)^vbox`),
		regexp.MustCompile(`(?i)vmware`),
		regexp.MustCompile(`(?i)hyper-?v`),
		regexp.MustCompile(`(?i)vethernet`),
		regexp.MustCompile(`(?i)npcap`),
		regexp.MustCompile(`(?i)^tun\d*$`),
		regexp.MustCompile(`(?i)^tap\d*$`),
		regexp.MustCompile(`(?i)^wg\d*$`),
		regexp.MustCompile(`(?i)^utun\d*$`),
		regexp.MustCompile(`(?i)zerotier`),
		regexp.MustCompile(`(?i)^zt`),
		regexp.MustCompile(`(?i)tailscale`),
		regexp.MustCompile(`(?i)^ppp\d*$`),
		regexp.MustCompile(`(?i)bridge`),
		regexp.MustCompile(`(?i)^br-`),
		regexp.MustCompile(`(?i)^br\d+$`),
		regexp.MustCompile(`(?i)^cni`),
		regexp.MustCompile(`(?i)flannel`),
		regexp.MustCompile(`(?i)weave`),
		regexp.MustCompile(`(?i)kube`),
		regexp.MustCompile(`(?i)isatap`),
		regexp.MustCompile(`(?i)teredo`),
		regexp.MustCompile(`(?i)bluetooth`),
		regexp.MustCompile(`(?i)^awdl\d*$`),
		regexp.MustCompile(`(?i)^llw\d*$`),
		regexp.MustCompile(`(?i)p2p`),
	}
)

const (
	scorePhysical  = 0
	scoreUnknown   = 10
	scoreVirtual   = 20
	scoreLinkLocal = 1000
)

// interfaceScore ranks an interface name by how likely it is to be a
// real, usable network interface. Lower scores are tried first.
func interfaceScore(name string) int {
	for _, re := range physicalInterfacePatterns {
		if re.MatchString(name) {
			return scorePhysical
		}
	}
	for _, re := range virtualInterfacePatterns {
		if re.MatchString(name) {
			return scoreVirtual
		}
	}
	return scoreUnknown
}

// GetLocalEndpoints returns "ip:port" strings (bracketed for IPv6, e.g.
// "[fe80::1]:51820") for every usable, non-loopback IP address bound to a
// network interface on this host. The list is ordered with interfaces most
// likely to be a genuine host network (wired/Wi-Fi) first, and interfaces
// that are typically synthetic (Docker, VPN tunnels, hypervisor bridges,
// etc.) last, so callers should try the results roughly in order.
//
// excludeInterface, if non-empty, is skipped entirely - this is normally the
// name of our own WireGuard/TUN interface, whose address is the tunnel IP
// and not a useful endpoint to advertise.
//
// If interfaces cannot be enumerated (e.g. insufficient OS permissions),
// an info message is logged and an empty slice is returned.
func GetLocalEndpoints(port uint16, excludeInterface string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Info("Unable to enumerate local network interfaces, localEndpoints will not be reported: %v", err)
		return nil
	}

	type candidate struct {
		score int
		ip    string
	}
	var candidates []candidate

	for _, iface := range ifaces {
		if excludeInterface != "" && iface.Name == excludeInterface {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			logger.Debug("Unable to read addresses for interface %s: %v", iface.Name, err)
			continue
		}

		baseScore := interfaceScore(iface.Name)

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}

			score := baseScore
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				score += scoreLinkLocal
			}

			candidates = append(candidates, candidate{score: score, ip: ip.String()})
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})

	portStr := strconv.Itoa(int(port))
	endpoints := make([]string, 0, len(candidates))
	for _, c := range candidates {
		endpoints = append(endpoints, net.JoinHostPort(c.ip, portStr))
	}
	return endpoints
}

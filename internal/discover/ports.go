package discover

// Naming a service from the port it answered on.
//
// A port number is evidence, not proof: anything may listen anywhere. But on a
// home network the convention holds overwhelmingly, and "192.168.1.52 offers
// SSH" is a far more useful line than "192.168.1.52 port 22".
//
// The list is deliberately short. It covers what turns up on a household network
// and stops there, a full IANA table would name thousands of ports nobody has
// ever run, and every extra entry is another chance to label something wrongly
// with confidence.

// ServiceForPort names the service conventionally found on a port, or empty if
// the port carries no useful convention.
//
// proto is "tcp" or "udp"; a few numbers mean different things on each.
func ServiceForPort(port uint16, proto string) string {
	if proto == "udp" {
		if name, ok := udpPorts[port]; ok {
			return name
		}
		return ""
	}
	return tcpPorts[port]
}

// tcpPorts covers the services a home network actually runs.
var tcpPorts = map[uint16]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	548:   "AFP",
	554:   "RTSP",
	631:   "IPP",
	853:   "DNS over TLS",
	993:   "IMAPS",
	995:   "POP3S",
	1883:  "MQTT",
	3000:  "HTTP",
	3306:  "MySQL",
	3389:  "RDP",
	5000:  "HTTP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	7000:  "AirPlay",
	8006:  "Proxmox",
	8080:  "HTTP",
	8096:  "Jellyfin",
	8123:  "Home Assistant",
	8443:  "HTTPS",
	9000:  "HTTP",
	9100:  "Printing",
	32400: "Plex",
	51413: "BitTorrent",
}

// udpPorts is shorter still: most UDP services announce themselves by other
// means, and the ones here are the ones that do not.
var udpPorts = map[uint16]string{
	53:    "DNS",
	67:    "DHCP",
	123:   "NTP",
	161:   "SNMP",
	500:   "IPsec",
	1900:  "SSDP",
	5353:  "mDNS",
	51820: "WireGuard",
}

// PortIsInteresting reports whether a listening port is worth recording.
//
// Ephemeral ports are where outbound connections come *from*, not where services
// live. Recording them would fill a device's service list with noise that
// changes every connection.
func PortIsInteresting(port uint16) bool {
	return port > 0 && port < 32768
}

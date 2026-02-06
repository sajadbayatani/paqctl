package gfk

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func parseTCPFlags(flags string) layers.TCPFlag {
	flags = strings.ToUpper(flags)
	var out layers.TCPFlag
	if strings.Contains(flags, "F") {
		out |= layers.TCPFlagFin
	}
	if strings.Contains(flags, "S") {
		out |= layers.TCPFlagSyn
	}
	if strings.Contains(flags, "R") {
		out |= layers.TCPFlagRst
	}
	if strings.Contains(flags, "P") {
		out |= layers.TCPFlagPsh
	}
	if strings.Contains(flags, "A") {
		out |= layers.TCPFlagAck
	}
	if strings.Contains(flags, "U") {
		out |= layers.TCPFlagUrg
	}
	if strings.Contains(flags, "E") {
		out |= layers.TCPFlagEce
	}
	if strings.Contains(flags, "C") {
		out |= layers.TCPFlagCwr
	}
	return out
}

func flagsMatch(tcp *layers.TCP, required layers.TCPFlag) bool {
	if required&layers.TCPFlagAck != 0 && !tcp.ACK {
		return false
	}
	if required&layers.TCPFlagPsh != 0 && !tcp.PSH {
		return false
	}
	if required&layers.TCPFlagSyn != 0 && !tcp.SYN {
		return false
	}
	if required&layers.TCPFlagRst != 0 && !tcp.RST {
		return false
	}
	if required&layers.TCPFlagFin != 0 && !tcp.FIN {
		return false
	}
	if required&layers.TCPFlagUrg != 0 && !tcp.URG {
		return false
	}
	if required&layers.TCPFlagEce != 0 && !tcp.ECE {
		return false
	}
	if required&layers.TCPFlagCwr != 0 && !tcp.CWR {
		return false
	}
	return true
}

func resolveLocalIP(dstIP string) (net.IP, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(dstIP, "53"), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP == nil {
		return nil, errors.New("failed to resolve local ip")
	}
	return localAddr.IP, nil
}

func runtimeGOOS() string {
	return runtime.GOOS
}

func pickInterfaceForIP(dstIP string) (string, error) {
	localIP, err := resolveLocalIP(dstIP)
	if err != nil {
		return "", err
	}
	localIP = localIP.To4()
	if localIP == nil {
		return "", errors.New("local ip is not IPv4")
	}

	if runtimeGOOS() == "windows" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			return "", err
		}
		for _, dev := range devs {
			for _, addr := range dev.Addresses {
				if addr.IP != nil && addr.IP.To4() != nil && addr.IP.Equal(localIP) {
					return dev.Name, nil
				}
			}
		}
		return "", errors.New("pcap device not found for local ip")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip != nil && ip.To4() != nil && ip.Equal(localIP) {
				return iface.Name, nil
			}
		}
	}
	return "", errors.New("interface not found for local ip")
}

package gfk

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/SamNet-dev/paqctl/gfk/internal/config"
)

type vioSniffPacket struct {
	payload  []byte
	srcIP    net.IP
	srcPort  int
}

func RunVIOClient(ctx context.Context, cfg config.Config) error {
	log.Printf("VIO client starting")

	pcapIface := cfg.VIO.Interface
	if pcapIface == "" {
		ifname, err := pickInterfaceForIP(cfg.VPSIP)
		if err == nil {
			pcapIface = ifname
		}
	}
	if pcapIface == "" {
		return errors.New("vio.iface is required (pcap capture interface not found)")
	}

	flags := parseTCPFlags(cfg.VIO.TCPFlags)
	sender, srcIP, err := newPacketSenderClient(cfg, pcapIface)
	if err != nil {
		return err
	}
	defer sender.Close()

	sniffCh := make(chan vioSniffPacket, 1024)
	go sniffLoop(ctx, pcapIface, buildClientFilter(cfg), flags, sniffCh)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.VIO.UDPClientPort})
	if err != nil {
		return err
	}
	defer udpConn.Close()
	quicAddr := &net.UDPAddr{IP: net.ParseIP(cfg.QUIC.LocalIP), Port: cfg.QUIC.ClientPort}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-sniffCh:
				_, _ = udpConn.WriteToUDP(pkt.payload, quicAddr)
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return err
		}
		payload := append([]byte(nil), buf[:n]...)
		if err := sender.SendTCP(srcIP, net.ParseIP(cfg.VPSIP), cfg.VIO.TCPClientPort, cfg.VIO.TCPServerPort, flags, payload); err != nil {
			log.Printf("vio client send error: %v", err)
		}
	}
}

func RunVIOServer(ctx context.Context, cfg config.Config) error {
	log.Printf("VIO server starting")

	pcapIface := cfg.VIO.Interface
	if pcapIface == "" {
		ifname, err := pickInterfaceForIP(cfg.VPSIP)
		if err == nil {
			pcapIface = ifname
		}
	}
	if pcapIface == "" {
		return errors.New("vio.iface is required (pcap capture interface not found)")
	}

	flags := parseTCPFlags(cfg.VIO.TCPFlags)
	sender, srcIP, err := newPacketSenderServer(cfg, pcapIface)
	if err != nil {
		return err
	}
	defer sender.Close()

	sniffCh := make(chan vioSniffPacket, 1024)
	go sniffLoop(ctx, pcapIface, buildServerFilter(cfg), flags, sniffCh)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.VIO.UDPServerPort})
	if err != nil {
		return err
	}
	defer udpConn.Close()
	quicAddr := &net.UDPAddr{IP: net.ParseIP(cfg.QUIC.LocalIP), Port: cfg.QUIC.ServerPort}

	var mu sync.RWMutex
	clientIP := net.ParseIP("0.0.0.0")
	clientPort := 0

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case pkt := <-sniffCh:
				mu.Lock()
				clientIP = pkt.srcIP
				clientPort = pkt.srcPort
				mu.Unlock()
				_, _ = udpConn.WriteToUDP(pkt.payload, quicAddr)
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return err
		}

		mu.RLock()
		dstIP := append([]byte(nil), clientIP...)
		dstPort := clientPort
		mu.RUnlock()
		if dstPort == 0 || dstIP == nil {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if err := sender.SendTCP(srcIP, dstIP, cfg.VIO.TCPServerPort, dstPort, flags, payload); err != nil {
			log.Printf("vio server send error: %v", err)
		}
	}
}

func sniffLoop(ctx context.Context, iface, filter string, requiredFlags layers.TCPFlag, out chan<- vioSniffPacket) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("pcap open error: %v", err)
		return
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("pcap filter error: %v", err)
		return
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-src.Packets():
			if pkt == nil {
				continue
			}
			tcpLayer := pkt.Layer(layers.LayerTypeTCP)
			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			if tcpLayer == nil || ipLayer == nil {
				continue
			}
			tcp := tcpLayer.(*layers.TCP)
			ip := ipLayer.(*layers.IPv4)
			if !flagsMatch(tcp, requiredFlags) {
				continue
			}
			if len(tcp.Payload) == 0 {
				continue
			}
			out <- vioSniffPacket{payload: append([]byte(nil), tcp.Payload...), srcIP: ip.SrcIP, srcPort: int(tcp.SrcPort)}
		}
	}
}

func buildClientFilter(cfg config.Config) string {
	return fmt.Sprintf("tcp and src host %s and src port %d", cfg.VPSIP, cfg.VIO.TCPServerPort)
}

func buildServerFilter(cfg config.Config) string {
	return fmt.Sprintf("tcp and dst host %s and dst port %d", cfg.VPSIP, cfg.VIO.TCPServerPort)
}

func newPacketSenderClient(cfg config.Config, iface string) (PacketSender, net.IP, error) {
	srcIPStr := cfg.VIO.MyIP
	if srcIPStr == "" {
		ip, err := resolveLocalIP(cfg.VPSIP)
		if err == nil {
			srcIPStr = ip.String()
		}
	}
	if srcIPStr == "" {
		return nil, nil, errors.New("vio.my_ip is required or auto-detect failed")
	}
	if isWindows() {
		localMAC, err := net.ParseMAC(cfg.VIO.LocalMAC)
		if err != nil {
			return nil, nil, errors.New("vio.local_mac is required on Windows")
		}
		gwMAC, err := net.ParseMAC(cfg.VIO.GatewayMAC)
		if err != nil {
			return nil, nil, errors.New("vio.gateway_mac is required on Windows")
		}
		sender, err := newPacketSender(iface, localMAC, gwMAC)
		ip := net.ParseIP(srcIPStr)
		if ip == nil {
			return nil, nil, errors.New("invalid vio.my_ip")
		}
		return sender, ip, err
	}
	sender, err := newPacketSender("", nil, nil)
	ip := net.ParseIP(srcIPStr)
	if ip == nil {
		return nil, nil, errors.New("invalid vio.my_ip")
	}
	return sender, ip, err
}

func newPacketSenderServer(cfg config.Config, iface string) (PacketSender, net.IP, error) {
	if isWindows() {
		localMAC, err := net.ParseMAC(cfg.VIO.LocalMAC)
		if err != nil {
			return nil, nil, errors.New("vio.local_mac is required on Windows")
		}
		gwMAC, err := net.ParseMAC(cfg.VIO.GatewayMAC)
		if err != nil {
			return nil, nil, errors.New("vio.gateway_mac is required on Windows")
		}
		sender, err := newPacketSender(iface, localMAC, gwMAC)
		ip := net.ParseIP(cfg.VPSIP)
		if ip == nil {
			return nil, nil, errors.New("invalid vps_ip")
		}
		return sender, ip, err
	}
	sender, err := newPacketSender("", nil, nil)
	ip := net.ParseIP(cfg.VPSIP)
	if ip == nil {
		return nil, nil, errors.New("invalid vps_ip")
	}
	return sender, ip, err
}

func isWindows() bool {
	return runtimeGOOS() == "windows"
}

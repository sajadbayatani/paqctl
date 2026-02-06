//go:build windows

package gfk

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketSender interface {
	SendTCP(srcIP, dstIP net.IP, srcPort, dstPort int, flags TCPFlag, payload []byte) error
	Close() error
}

type pcapSender struct {
	handle     *pcap.Handle
	localMAC   net.HardwareAddr
	gatewayMAC net.HardwareAddr
}

func newPacketSender(iface string, localMAC, gatewayMAC net.HardwareAddr) (PacketSender, error) {
	if iface == "" {
		return nil, errors.New("pcap interface is required on Windows")
	}
	h, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &pcapSender{handle: h, localMAC: localMAC, gatewayMAC: gatewayMAC}, nil
}

func (s *pcapSender) SendTCP(srcIP, dstIP net.IP, srcPort, dstPort int, flags TCPFlag, payload []byte) error {
	if s.handle == nil {
		return errors.New("pcap handle not initialized")
	}
	if s.localMAC == nil || s.gatewayMAC == nil {
		return errors.New("local_mac and gateway_mac are required on Windows")
	}

	eth := &layers.Ethernet{
		SrcMAC:       s.localMAC,
		DstMAC:       s.gatewayMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
		
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     0,
		Ack:     0,
		Window:  1024,
		ACK:     flags&TCPFlagAck != 0,
		PSH:     flags&TCPFlagPsh != 0,
		SYN:     flags&TCPFlagSyn != 0,
		RST:     flags&TCPFlagRst != 0,
		FIN:     flags&TCPFlagFin != 0,
		URG:     flags&TCPFlagUrg != 0,
		ECE:     flags&TCPFlagEce != 0,
		CWR:     flags&TCPFlagCwr != 0,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0x00}},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x08}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		},
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	_ = s.handle.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return s.handle.WritePacketData(buf.Bytes())
}

func (s *pcapSender) Close() error {
	if s.handle == nil {
		return nil
	}
	s.handle.Close()
	return nil
}

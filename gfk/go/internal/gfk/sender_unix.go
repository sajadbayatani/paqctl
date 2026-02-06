//go:build !windows

package gfk

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

type PacketSender interface {
	SendTCP(srcIP, dstIP net.IP, srcPort, dstPort int, flags layers.TCPFlag, payload []byte) error
	Close() error
}

type rawSender struct {
	conn *ipv4.RawConn
}

func newPacketSender(_ string, _ net.HardwareAddr, _ net.HardwareAddr) (PacketSender, error) {
	pc, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	raw, err := ipv4.NewRawConn(pc)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return &rawSender{conn: raw}, nil
}

func (s *rawSender) SendTCP(srcIP, dstIP net.IP, srcPort, dstPort int, flags layers.TCPFlag, payload []byte) error {
	if srcIP == nil || dstIP == nil {
		return errors.New("invalid src/dst ip")
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
		ACK:     flags&layers.TCPFlagAck != 0,
		PSH:     flags&layers.TCPFlagPsh != 0,
		SYN:     flags&layers.TCPFlagSyn != 0,
		RST:     flags&layers.TCPFlagRst != 0,
		FIN:     flags&layers.TCPFlagFin != 0,
		URG:     flags&layers.TCPFlagUrg != 0,
		ECE:     flags&layers.TCPFlagEce != 0,
		CWR:     flags&layers.TCPFlagCwr != 0,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0x00}},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x08}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		},
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}

	hdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(buf.Bytes()),
		TTL:      64,
		Protocol: int(layers.IPProtocolTCP),
		Src:      srcIP,
		Dst:      dstIP,
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return s.conn.WriteTo(hdr, buf.Bytes(), nil)
}

func (s *rawSender) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

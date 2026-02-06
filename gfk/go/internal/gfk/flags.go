package gfk

// TCPFlag is a local flag bitmask to avoid relying on gopacket's TCPFlag,
// which is not available in older gopacket versions.
type TCPFlag uint8

const (
	TCPFlagFin TCPFlag = 0x01
	TCPFlagSyn TCPFlag = 0x02
	TCPFlagRst TCPFlag = 0x04
	TCPFlagPsh TCPFlag = 0x08
	TCPFlagAck TCPFlag = 0x10
	TCPFlagUrg TCPFlag = 0x20
	TCPFlagEce TCPFlag = 0x40
	TCPFlagCwr TCPFlag = 0x80
)

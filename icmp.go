package tcpip

import (
	"errors"
	"golang.org/x/sys/unix"
)

// RFC792 https://tools.ietf.org/html/rfc792
type IcmpEchoHeader struct {
	Type			uint8
	Code			uint8
	HeaderChecksum		uint16
	Idenifier		uint16
	SequenceNumber	uint16
}

type Icmp struct {
	IcmpReplyHeader *IcmpEchoHeader
	Data            []byte
}

func(pm *PacketMan) IcmpEchoRequest(dstIp [4]byte, data []byte, seqNum uint16) (*Icmp, error) {
	if len(data) > (1400) {
		return nil, errors.New("Data should be up to 1472.")
	}
	key := pm.CreatePacket()	
	p := pm.packets[key]

	if err := p.createBaseIPv4Header(dstIp); err != nil {
		return nil, err
	}
	// IP header is 20 byte
	// ICMP header is 8 byte
	p.ipV4Header.TotalLength = uint16(28 + len(data))
	p.ipV4Header.Protocol = 1 // RFC790: https://tools.ietf.org/html/rfc790
	p.ipV4Header.FlagsAndFragmentOffset = 0x4000 // No flagments

	p.icmpEchoHeader = &IcmpEchoHeader{
		Type: 8, // for echo message. 
		Code: 0, // for echo message.
		HeaderChecksum: 0, // set to 0 before calculating checksum.
		Idenifier: uint16(randomIntnPlus(16)), 
		SequenceNumber: seqNum, 
	}

	// ICMP checksum (including data area not only header).
	icmpBytes, err := convertPacketStructToBytes(p.icmpEchoHeader, data)	
	if err != nil {
		return nil, err
	}
	p.icmpEchoHeader.HeaderChecksum = checkSum(icmpBytes)

	if err = p.sendPacket(SEND_ICMP, data); err != nil {
		return nil, err
	}

	icmpReply := Icmp{}
	replyData := make([]byte, 1514)

	// todo: implement timeout accurately.
	for i := 0; i < 101; i++ {
		if i == 100 {
			return nil, errors.New("No ICMP reply.")
		}
		l, _, err := unix.Recvfrom(pm.fd, replyData, 0)
		if err != nil {
			return nil, err
		}

		// ICMP packet is 42 bytes at least.
		if l < 42 {
			continue
		}
		
		// Checking whether it is ICMP in protocol of the reply IP header
		if replyData[23] != 1 {
			continue
		}
		
		// Checking whether the IP header is correct.
		if _, err := filterIpV4Header(replyData, p); err != nil {
			continue	
		}

		// Converting reply packet to ICMP header struct.
		err = convertPacketBytesToStruct(replyData[34:42], &icmpReply.IcmpReplyHeader)
		if err != nil {
			return nil, err
		}

		// The minimum size of ICMP echo reply packet is 42 bytes.
		// So if the packet is bigger than 42 bytes, That may have data area.
		if len(replyData) > 42 {
			icmpReply.Data = replyData[42:]
		}
		break
	}
	return &icmpReply, nil
}

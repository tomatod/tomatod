package tcpip

import (
	"errors"
)

// RFC768: https://tools.ietf.org/html/rfc768
type UdpHeader struct {
	SourcePort uint16
	DestinationPort uint16
	Length uint16
	CheckSum uint16
}

// There is pseudo header in UDP protocol. 
// pseudo header is included in the target data of caliculating checksum.
type UdpPseudoHeader struct {
	SourceAddress      [4]byte
	DestinationAddress [4]byte
	Zero               uint8
	Protocol           uint8
	UdpLength          uint16
}

type Udp struct {
	Header       *UdpHeader
	PseudoHeader *UdpPseudoHeader
	Data         []byte
}

var MAX_UDP_LENGTH int = 1400

func(pm *PacketMan) UdpRequest(srcPort uint16, dstIp [4]byte, dstPort uint16, data[]byte) ([]*Packet, error) {
	packets := []*Packet{}
	flagmentNum := int(len(data) / MAX_UDP_LENGTH) + 1
	for i := 0; i < flagmentNum; i++ {
		key := pm.CreatePacket()	
		p := pm.packets[key]

		if err := p.createBaseIPv4Header(dstIp); err != nil {
			return nil, err
		}
		p.ipV4Header.Protocol = 17 // RFC790: https://tools.ietf.org/html/rfc790
		if flagmentNum == 1 {
			p.ipV4Header.FlagsAndFragmentOffset = 0x4000 // No flagments
		} else {
			p.ipV4Header.FlagsAndFragmentOffset = uint16(MAX_UDP_LENGTH * i)
			if i != flagmentNum - 1 {
				p.ipV4Header.FlagsAndFragmentOffset += 1 << 13
			}
		}

		var udpLength int = 8 // UDP header size is 8 bytes.
		if flagmentNum - 1 == i {
			if data != nil {
				udpLength += len(data) % MAX_UDP_LENGTH
			}
		} else {
			udpLength += MAX_UDP_LENGTH
		}

		// 20 byte is IP header length
		p.ipV4Header.TotalLength = uint16(udpLength + 20)

		p.udpHeader = &UdpHeader {
			SourcePort: srcPort,
			DestinationPort: dstPort,
			Length: uint16(udpLength), 
			CheckSum: 0,
		}

		// In UDP, checksum is caliculated including pseudo header.
		pseudo := UdpPseudoHeader {
			SourceAddress: p.ipV4Header.SourceAddress,
			DestinationAddress: p.ipV4Header.DestinationAddress,
			Zero: 0,
			Protocol: p.ipV4Header.Protocol,
			UdpLength: p.udpHeader.Length,
		}

		udpBeforeCheckSum, err := convertPacketStructToBytes(&pseudo, p.udpHeader, data)
		if err != nil {
			return nil, err
		}
		p.udpHeader.CheckSum = checkSum(udpBeforeCheckSum)

		/*
		ipBeforeCheckSum, err := convertPacketStructToBytes(p.ipV4Header)
		if err != nil {
			return err
		}
		p.ipV4Header.HeaderCheckSum = checkSum(ipBeforeCheckSum)
		*/

		packets = append(packets, p)
	}
	
	for i := 0; i < len(packets); i++ {
		if err := packets[i].sendPacket(SEND_UDP, data); err != nil {
			return nil, err
		}
	}

	return packets, nil
}

// Filtering the IPv4 header of reply packet.
// todo: verify checksum of reply UDP header.
func filterUdpHeader(replyPacket []byte, p *Packet) (*Udp, error) {
	// IP Protocol is 34 bytes at the minimum.
	// UPD Header is 8 bytes.
	if len(replyPacket) < 42 {
		return nil, errors.New("This packet is too small for UDP protocol.")
	}
	if replyPacket[23] != 17 {
		return nil, errors.New("This packet is not UDP protocol.")
	}

	// Checking IP header.
	ipv4, err := filterIpV4Header(replyPacket, p)
	if err != nil {
		return nil, err
	}
	
	// checking source and destination port.
	repSrcPortBytes := (uint16(replyPacket[0]) << 8) + (uint16(replyPacket[1]))
	if p.udpHeader.SourcePort != repSrcPortBytes {
		return nil, errors.New("Source port is different from expected one.")
	}
	repDstPortBytes := (uint16(replyPacket[2]) << 8) + (uint16(replyPacket[3]))
	if p.udpHeader.SourcePort != repDstPortBytes {
		return nil, errors.New("Destination port is different from expected one.")
	}
	
	udp := Udp{}
	err = convertPacketBytesToStruct(ipv4.Data[:8], udp.Header)
	if err != nil {
		return nil, err
	}
	udp.Data = ipv4.Data[8:]
	udp.PseudoHeader.SourceAddress = ipv4.Header.SourceAddress
	udp.PseudoHeader.DestinationAddress = ipv4.Header.DestinationAddress
	udp.PseudoHeader.Zero = 0
	udp.PseudoHeader.Protocol = 17
	udp.PseudoHeader.UdpLength = uint16(len(ipv4.Data))

	return &udp, nil
}

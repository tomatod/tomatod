package tcpip

import (
	"errors"
	"reflect"
)

// RFC791: https://tools.ietf.org/html/rfc791
type IpV4Header struct {
	VersionAndIHL uint8
	TypeOfService uint8
	TotalLength uint16
	Identification uint16
	FlagsAndFragmentOffset uint16
	TimeToLive uint8
	Protocol uint8
	HeaderCheckSum uint16
	SourceAddress [4]byte
	DestinationAddress [4]byte
}

type IpV4 struct {
	Header *IpV4Header
	Data       []byte
}

func(p *Packet) createBaseIPv4Header(dstIp [4]byte) error {
	var dstMacAddr [6]byte
	ar := getArpRecordV4(dstIp)
	if ar == nil {
		// if arp table don't have arp record for destination ip address,
		// arp request is executed
		loging(LOG_DEBUG, "Target IP address is not found. ARP request is executed.")
		arh, err := p.packetMan.ArpRequest(dstIp)
		if err != nil {
			return err
		}
		dstMacAddr = arh.SrcHardwareAddress
	} else {
		dstMacAddr = ar.HardwareAddress
	}

	p.setNewEtherFrameForIP(dstMacAddr)

	srcIp, err := getIPv4FromInterface(p.packetMan.inf)
	if err != nil {
		return err
	}

	iph := IpV4Header{
		VersionAndIHL: 0x45,
		TypeOfService: 0, // I don't know well
		Identification: uint16(randomIntnPlus(16)),
		TimeToLive: 128, 
		HeaderCheckSum: 0,
		SourceAddress: srcIp,
		DestinationAddress: dstIp,
	}
	p.ipV4Header = &iph

	return nil
}

func(p *Packet) checksumIpV4() error {
	// IP Header checksum. That is probably only checksum of IP Header without data.
	ipBytes, err := convertPacketStructToBytes(p.ipV4Header)
	if err != nil {
		return err
	}
	p.ipV4Header.HeaderCheckSum = checkSum(ipBytes)
	return nil
}

// Filtering the IPv4 header of reply packet.
// todo: verify checksum of reply IP header.
func filterIpV4Header (replyPacket []byte, p *Packet) (*IpV4, error) {
	// Checking packet length. The minimum size of IP packet is 34 bytes.
	if len(replyPacket) < 34 {
		return nil, errors.New("This packet is too small for IPv4.")
	}
	// Checking whether the packet is IP.
	if !(replyPacket[12] == 0x08 && replyPacket[13] == 0x00) {
		return nil, errors.New("This packet is not IPv4 protocol.")
	}
	// Checking the Source IP address of the packets.
	// That is required to be same with the destination IP address of request packet.
	if !reflect.DeepEqual(p.ipV4Header.DestinationAddress[:], replyPacket[26:30]) {
		return nil, errors.New("Source IP address is different from expected one.")
	}
	// Checking the destination IP address.
	if !reflect.DeepEqual(p.ipV4Header.SourceAddress[:], replyPacket[30:34]) {
		return nil, errors.New("Destination IP address is different from expected one.")
	}

	// Converting packet to IP Header struct.
	replyIpHeader := IpV4Header{}
	err := convertPacketBytesToStruct(replyPacket[14:34], &replyIpHeader)
	if err != nil {
		return nil, err
	}
	ipv4 := IpV4{}
	ipv4.Header = &replyIpHeader
	if len(replyPacket) > 34 {
		ipv4.Data = replyPacket[34:]
	}

	return &ipv4, nil
}

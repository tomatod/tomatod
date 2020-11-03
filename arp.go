package tcpip

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"reflect"
	"bytes"
)

// RFC826: https://tools.ietf.org/html/rfc826
type ArpHeader struct {
	HardwareType       uint16
	ProtocolType       uint16
	HardwareLength     uint8
	ProtocolLength     uint8
	Operation          uint16
	SrcHardwareAddress [6]byte
	SrcIPAddress       [4]byte
	DstHardwareAddress [6]byte
	DstIPAddress       [4]byte
}

// obtaind pairs of IP and hardware addresses are Recorded by ArpReuest().
type ArpRecord struct {
	HardwareAddress [6]byte
	IPAddress [4]byte
}
type ArpTable []*ArpRecord

var arpTable ArpTable

func (pm *PacketMan) ArpRequest(dstIpv4 [4]byte) (*ArpHeader, error) {
	key := pm.CreatePacket()
	p := pm.packets[key]

	p.setNewEtherFrameForARP()

	srcIpv4, err := getIPv4FromInterface(pm.inf)
	if err != nil {
		return nil, err
	}

	// Ether type: RFC5342 https://tools.ietf.org/html/rfc5342#appendix-B.1
	p.arpHeader = &ArpHeader{
		HardwareType:       0x0001, // only 0x0001
		ProtocolType:       0x0800, // 0x0800  Internet Protocol Version 4 (IPv4)
		HardwareLength:     6,      // MAC address is 6 bytes.
		ProtocolLength:     4,      // IPv4 is 4 bytes.
		Operation:          0x0001, // Request is 1, Reply is 2
		SrcHardwareAddress: pm.macAddrBytes,
		SrcIPAddress:       srcIpv4,
		// Unknown at the time of request
		DstHardwareAddress: [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstIPAddress:       dstIpv4, // you want to know
	}

	if err = p.sendPacket(SEND_ARP, nil); err != nil {
		return nil, err
	}

	data := make([]byte, 1514)
	for {
		_, _, err := unix.Recvfrom(pm.fd, data, 0)
		if err != nil {
			return nil, err
		}
		// Protocol type number of ARP is 0x0806 in EthernetFrame.
		if !(data[12] == 0x08 && data[13] == 0x06) { 
			continue
		}
		// Checking IP address requested.
		if !reflect.DeepEqual(data[28:32], p.arpHeader.DstIPAddress[:]) {
			continue
		}
		loging(LOG_DEBUG, "Recvfrom() => ARP Reply")
		break
	}

	// ARP Packet start from 15 bytes.
	r := bytes.NewReader(data[14:])
	a := ArpHeader{}
	binary.Read(r, binary.BigEndian, &a)

	addArpRecord(&a)

	return &a, nil
}

func addArpRecord(arp *ArpHeader) {
	ar := ArpRecord {
		arp.SrcHardwareAddress,
		arp.SrcIPAddress,
	}
	for i, v := range arpTable {
		if v.IPAddress == ar.IPAddress {
			arpTable[i].HardwareAddress = ar.HardwareAddress
			return
		}
	}
	arpTable = append(arpTable, &ar)
}

func getArpRecordV4(ip [4]byte) *ArpRecord {
	for _, ar := range arpTable {
		for i, ips := range ar.IPAddress {
			if ip[i] != ips {
				break
			}
			if i == 3 {
				return ar
			}
		}
	}
	return nil
}

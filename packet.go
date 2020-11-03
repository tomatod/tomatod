package tcpip

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
)

type PacketMan struct {
	fd           int
	inf          *net.Interface
	macAddrBytes [6]byte
	packets      map[uint]*Packet
}

type Packet struct {
	packetMan 		*PacketMan
	data 			[]byte
	etherFrame 		*EtherFrame		 
	arpHeader       *ArpHeader     	 
	ipV4Header      *IpV4Header   	 
	icmpEchoHeader 	*IcmpEchoHeader  
	udpHeader      	*UdpHeader 		 
}

func CreatePacketMan(infName string) (*PacketMan, error) {
	inf, err := net.InterfaceByName(infName)
	if err != nil {
		return nil, err
	}

	p := &PacketMan{}
	p.inf = inf
	if err = p.createRawSocket(); err != nil {
		return nil, err
	}
	if err = p.bind(); err != nil {
		return nil, err
	}

	p.packets = map[uint]*Packet{}

	return p, nil
}

func (p *PacketMan) CreatePacket() uint {
	packet := Packet{}
	packet.packetMan = p	
	key := uint(randomIntnPlus(64))
	p.packets[key] = &packet
	return key
}

func (p *PacketMan) createRawSocket() error {
	var err error
	p.fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	return err
}

func (p *PacketMan) bind() error {
	var err error
	p.macAddrBytes, err = getMacAddrBytes(p.inf)
	if err != nil {
		return err
	}
	addr, err := p.makeAddr()
	if err != nil {
		return err
	}
	return unix.Bind(p.fd, addr)
}

func (p *PacketMan) makeAddr() (unix.Sockaddr, error) {
	var macAddrBytes8 [8]byte
	for i, b := range p.macAddrBytes {
		macAddrBytes8[i] = b
	}
	return &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		// Hatype: ,
		// Pkttype: ,
		Halen:   6,
		Addr:    macAddrBytes8,
		Ifindex: p.inf.Index,
	}, nil
}

func (p *Packet) send() error {
	var err error

	if _, err = unix.Write(p.packetMan.fd, p.data); err != nil {
		return err
	}

	return nil
}

const(
	SEND_ARP int = 1
	SEND_ICMP int = 2
	SEND_UDP int = 3
	SEND_TCP int = 4
)
func (p *Packet) sendPacket(sendType int, data []byte) error {
	if sendType == SEND_ICMP || sendType == SEND_UDP || sendType == SEND_TCP {
		if err := p.checksumIpV4(); err != nil {
			return err
		}
	}
	var typeOk bool
	if sendType == SEND_ARP {
		bytes, err := convertPacketStructToBytes(p.etherFrame, p.arpHeader)
		if err != nil {
			return err
		}
		p.data = bytes
		typeOk = true
	}
	if sendType == SEND_ICMP {
		bytes, err := convertPacketStructToBytes(p.etherFrame, p.ipV4Header, p.icmpEchoHeader)
		if err != nil {
			return err
		}
		p.data = bytes
		typeOk = true
	}
	if sendType == SEND_UDP {
		bytes, err := convertPacketStructToBytes(p.etherFrame, p.ipV4Header, p.udpHeader)
		if err != nil {
			return err
		}
		p.data = bytes
		typeOk = true
	}
	if typeOk {
		if data != nil {
			p.data = append(p.data, data...)
		}
		if err := p.send(); err != nil {
			return err
		}
		return nil
	}
	return errors.New("sendType is not exist.")
}

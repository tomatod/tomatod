package tcpip

type EtherFrame struct {
	DstMac       [6]byte
	SrcMac       [6]byte
	ProtocolType uint16
}

func (p *Packet) setNewEtherFrame() {
	p.etherFrame = &EtherFrame{}
	for i := 0; i < len(p.etherFrame.SrcMac); i++ {
		p.etherFrame.SrcMac[i] = p.packetMan.macAddrBytes[i]
	}
}

func (p *Packet) setNewEtherFrameForARP() {
	p.setNewEtherFrame()

	// broadcast
	p.etherFrame.DstMac = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// see RFC5342 https://tools.ietf.org/html/rfc5342#appendix-B.1
	p.etherFrame.ProtocolType = 0x0806 // 0x0806  Address Resolution Protocol (ARP)
}

func (p *Packet) setNewEtherFrameForIP(dstMac [6]byte) {
	p.setNewEtherFrame()

	// broadcast
	p.etherFrame.DstMac = dstMac

	// see RFC5342 https://tools.ietf.org/html/rfc5342#appendix-B.1
	p.etherFrame.ProtocolType = 0x0800 // 0x0800 IPv4
}

package tcpip

/*
import (
	"strings"
	"bytes"
	"golang.org/x/sys/unix"
)

// RFC1035 : https://tools.ietf.org/html/rfc1035

type DnsHeader struct {
	Id      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

type DnsQuestionSectionExQName struct {
	QType  uint16
	QClass uint16
}
type DnsQuestionSection struct {
	Name             []byte
	FixedLengthParam *DnsQuestionSectionExQName
}

type DnsResourceRecordExNameAndRdata struct {
	Type     uint16
	Class    uint16
	Ttl      uint16
	RdLength uint16
}
type DnsResourceRecord struct {
	Name             []byte
	FixedLengthParam *DnsResourceRecordExNameAndRdata
	Rdata            []byte
}

type Dns struct {
	Header     *DnsHeader
	Question   []*DnsQuestionSection
	Answer     []*DnsResourceRecord
	Authority  []*DnsResourceRecord
	Additional []*DnsResourceRecord
}

// QName : https://tools.ietf.org/html/rfc1035#section-3.2.2
// QClass: https://tools.ietf.org/html/rfc1035#section-3.2.4
const (
	QTYPE_A uint16 = 0x01

	QCLASS_IN uint16 = 0x01
)

// DNS message format: https://tools.ietf.org/html/rfc1035#section-4
func(pm *PacketMan) DnsQuery(srcPort uint16, dstIp [4]byte, dstPort uint16, qType uint16, domainName string, isRecursive bool) (*Dns, error) {
	// DNS header
	header := DnsHeader {
		// Id: uint16(randomIntnPlus(16)),
		Id: 0,
		QdCount: 1, // the number of question sections (typically 1)
		// the following 3 parameter is probably ignored in query.
		AnCount: 0, 
		NsCount: 0,
		ArCount: 0,
	}
	// DNS header flags.
	qr := 0
	opcode := 0
	aa := 0 
	tc := 0
	rd := 0 
	if isRecursive {
		rd = 1
	}
	ra := 0
	z  := 0 // this must be zero.
	rcode := 0 
	header.Flags += uint16((qr << 15) + (opcode << 11) + (aa << 10) + (tc << 9) + (rd << 8) + (ra << 7) + (z << 4) + rcode)

	// Question section
	question := DnsQuestionSectionExQName {
		QType:  qType,
		QClass: QCLASS_IN,
	}
	qname := createQName(domainName)

	data, err := convertPacketStructToBytes(&header, qname, &question)
	if err != nil {
		loging(LOG_DEBUG, err)
		return nil, err
	}

	reqPackets, err := pm.UdpRequest(srcPort, dstIp, dstPort, data)
	if err != nil {
		loging(LOG_DEBUG, err)
		return nil, err
	}

	replyData := make([]byte, 1514)
	for {
		i, _, err := unix.Recvfrom(pm.fd, replyData, 0)
		if err != nil {
			return nil, err
		}
		
		// Etherframe 14 byte + IPv4 header 20 byte + UDP header 8 byte + DNS Header 12 byte.
		if i < 54 {
			continue
		}

		udp, err := filterUdpHeader(replyData, reqPackets[0])
		if err != nil {
			return nil, err
		}

		replyDns := Dns{}
		if replyDns.Header, err = getDnsHeaderFromReply(udp); err != nil {
			return nil, err 
		}

	}
}

func createQName(domainName string) []byte {
	var domainNameBytes []byte
	doms := strings.Split(domainName, ".")
	for _, dom := range doms {
		bytes := []byte(dom) // translate to ASCII Code
		domainNameBytes = append(domainNameBytes, byte(len(bytes))) // length for each dot delimiter
		domainNameBytes = append(domainNameBytes, bytes...) // ASCII Codes for each dot delimiter
	}
	domainNameBytes = append(domainNameBytes, 0x00)
	return domainNameBytes
}

func getDnsQuestionSectionFromReply(udp *Udp) (*DnsQuestionSection, error) {
}

func getDnsResourceRecord(udp *Udp) ([]*DnsResourceRecord, error) {
}

func getDnsHeaderFromReply(udp *Udp) (*DnsHeader, error) {
}

func findNameFromDnsHeaderOrSection(dns *Dns, bytes []byte) (int, error) {
}
*/

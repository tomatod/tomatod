package tcpip

import (
	"encoding/binary"
	"bytes"
	"time"
	"math/rand"
	"errors"
	"net"
	"fmt"
)

// why 8 bytes ? => syscall.SockaddrLinklayer.Addr is required 8 bytes.
func getMacAddrBytes(inf *net.Interface) ([6]byte, error) {
	macAddrSlice := []byte(inf.HardwareAddr)
	
	var macAddrBytes [6]byte

	for i := 0; i < len(macAddrSlice); i++ {
		macAddrBytes[i] = macAddrSlice[i]
	} 

	return macAddrBytes, nil
}

func getIPv4FromInterface(inf *net.Interface) ([4]byte, error) {
	var ipv4Bytes [4]byte

	addrs, err :=inf.Addrs()
	if err != nil {
		return ipv4Bytes, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				for i, b := range []byte(ipv4) {
					ipv4Bytes[i] = b
				}
				return ipv4Bytes, nil
			}
		}
	}

	return ipv4Bytes, errors.New("getIPv4FromInterface: IPv4 is not found in " + inf.Name + ".")
}

// print []bytes easy to see
func outputHexadecimal (b []byte) {
	if logLevel != LOG_DEBUG {
		return
	}
	loging(LOG_DEBUG, "Output binary:", len(b), "byte")
	for i := 0; i < len(b); i++ {
		fmt.Printf("%02x ", b[i])
		if (i + 1) % 16 == 0 {
			fmt.Println()
		}
	}
	fmt.Println()
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | host>>8
}

// this implementation is incorect.
func randomIntnPlus(bits int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(2^(bits+1) -1)
}

// the 16 bit one's complement of the one's complement sum of all 16 bit words.
func checkSum(data []byte) uint16 {
	if len(data) % 2 != 0 {
		data = append(data, 0x00)
	}
	var sum uint32
	for i := 0; i < len(data); i+=2 {
		for j := 0; j < 2; j++ {
			sum += uint32(data[i+j]) << ((1-j)*8)
		}
	}
	complementSum := uint16((sum & 0x0000ffff) + ((sum & 0xffff0000) >> 16))
	return 0xffff - complementSum
}

func convertPacketStructToBytes(structs ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, st := range structs {
		if err := binary.Write(buf, binary.BigEndian, st); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func convertPacketBytesToStruct(data []byte, struc interface{} ) error {
	r := bytes.NewReader(data)
	return binary.Read(r, binary.BigEndian, struc)
}

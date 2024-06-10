package cidrencode

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"

	"github.com/projectdiscovery/mapcidr"
)

const (
	MAGIC_BYTE = byte(1)
)

func Search(id string, ip net.IP) bool {
	file, err := os.OpenFile(file(id), os.O_RDONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close() // Make sure to close the file when the function returns

	b := make([]byte, 8)
	file.ReadAt(b, 0)
	offset := int64(binary.LittleEndian.Uint64(b))

	b = make([]byte, 1)
	file.ReadAt(b, int64(mapcidr.Inet_aton(ip))-offset)
	return (int64(b[0]) == int64(MAGIC_BYTE))
}

func Encode(id string, networks []*net.IPNet) {
	file, err := os.OpenFile(file(id), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close() // Make sure to close the file when the function returns

	ips := []int64{}
	for _, network := range networks {
		first, last, _ := mapcidr.AddressRange(network)
		ips = append(ips, mapcidr.Inet_aton(first), mapcidr.Inet_aton(last))
	}

	offset := findMin(ips) - int64(reflect.TypeOf(int64(0)).Size())
	log.Printf("Offset: %d", offset)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(offset))
	file.WriteAt(b, 0)

	for _, network := range networks {
		first, last, _ := mapcidr.AddressRange(network)
		ipRange := mapcidr.Inet_aton(last) - mapcidr.Inet_aton(first) + 1
		log.Printf("CIDR: %s, IP Range: %d", network, ipRange)
		b := make([]byte, ipRange)
		for i := 0; i < len(b); i++ {
			b[i] = MAGIC_BYTE
		}
		file.WriteAt(b, int64(mapcidr.Inet_aton(first))-offset)
	}
}

func file(id string) string {
	return fmt.Sprintf("./%s.acl", id)
}

func findMin(a []int64) int64 {
	min := a[0]
	for _, v := range a {
		if v < min {
			min = v
		}
	}
	return min
}

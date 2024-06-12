package cidrencode

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"reflect"

	"github.com/projectdiscovery/mapcidr"
)

const (
	MAGIC_BYTE = byte(1)
)

func Calculate(networks []*net.IPNet) (int64, int64, int64) {
	ips := convertToRangePairs(networks)
	min, max := findMinMax(ips)
	estimatedFileSize := max - min
	return min, max, estimatedFileSize
}

func Search(file *os.File, ip *net.IP) bool {
	b := make([]byte, 8)
	file.ReadAt(b, 0)
	offset := int64(binary.LittleEndian.Uint64(b))

	b = make([]byte, 1)
	file.ReadAt(b, int64(mapcidr.Inet_aton(*ip))-offset)
	return (int64(b[0]) == int64(MAGIC_BYTE))
}

func Encode(file *os.File, networks []*net.IPNet) {
	min, _, estimatedFileSize := Calculate(networks)
	log.Printf("Estimated File Size: %s\n", BytesToHumanReadable(estimatedFileSize))
	offset := min - int64(reflect.TypeOf(int64(0)).Size())
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

func BytesToHumanReadable(bytes int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	if bytes < 10 {
		return fmt.Sprintf("%d B", bytes) // Handle small bytes directly
	}
	log := math.Log2(float64(bytes))
	exp := int(log / 10.0) // 10 because log2(1024) is 10
	divisor := math.Pow(1024, float64(exp))
	humanReadable := float64(bytes) / divisor
	return fmt.Sprintf("%.2f %s", humanReadable, units[exp])
}

func findMinMax(a []int64) (int64, int64) {
	min := a[0]
	for _, v := range a {
		if v < min {
			min = v
		}
	}
	max := a[0]
	for _, v := range a {
		if v > max {
			max = v
		}
	}
	return min, max
}

func convertToRangePairs(networks []*net.IPNet) []int64 {
	ips := []int64{}
	for _, network := range networks {
		first, last, _ := mapcidr.AddressRange(network)
		ips = append(ips, mapcidr.Inet_aton(first), mapcidr.Inet_aton(last))
	}
	return ips
}

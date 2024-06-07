package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/projectdiscovery/mapcidr"
)

const (
	MAGIC_BYTE = byte(1)
)

var (
	id     = flag.String("id", "", "ID to use for the generation")
	encode = flag.Bool("encode", false, "Encode the CIDRs")
	search = flag.String("search", "", "Search for a IP in the CIDRs")
)

func main() {
	flag.Parse()
	filePath := fmt.Sprintf("./data/%s.acl", *id)
	if *encode {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("failed to open file: %s", err)
		}
		defer file.Close() // Make sure to close the file when the function returns

		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", err)
		}
		str := string(stdin)
		cidrs := strings.Split(strings.TrimSuffix(str, "\n"), "\n")

		ips := []int64{}
		for _, cidr := range cidrs {
			if strings.HasPrefix(cidr, "#") || strings.HasPrefix(cidr, "//") || cidr == "" {
				continue
			}

			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("Skipping invalid CIDR %s: %s", cidr, err)
				continue
			}
			first, last, _ := mapcidr.AddressRange(network)
			ips = append(ips, mapcidr.Inet_aton(first), mapcidr.Inet_aton(last))
		}

		offset := findMin(ips) - int64(reflect.TypeOf(int64(0)).Size())
		log.Printf("Offset: %d", offset)
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(offset))
		file.WriteAt(b, 0)

		for _, cidr := range cidrs {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("Skipping invalid CIDR %s: %s", cidr, err)
				continue
			}
			first, last, _ := mapcidr.AddressRange(network)
			ipRange := mapcidr.Inet_aton(last) - mapcidr.Inet_aton(first) + 1
			log.Printf("CIDR: %s, IP Range: %d", cidr, ipRange)
			b := make([]byte, ipRange)
			for i := 0; i < len(b); i++ {
				b[i] = MAGIC_BYTE
			}
			file.WriteAt(b, int64(mapcidr.Inet_aton(first))-offset)
		}
	} else if *search != "" {
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open file: %s", err)
		}
		defer file.Close() // Make sure to close the file when the function returns

		b := make([]byte, 8)
		file.ReadAt(b, 0)
		offset := int64(binary.LittleEndian.Uint64(b))

		b = make([]byte, 1)
		ip := net.ParseIP(*search)
		file.ReadAt(b, int64(mapcidr.Inet_aton(ip))-offset)
		exists := int64(b[0]) == int64(MAGIC_BYTE)
		log.Printf("Exists: %t", (int64(b[0]) == int64(MAGIC_BYTE)))
		if !exists {
			os.Exit(1)
		}
	}
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

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jmoney/cidr-encoder/internal/cidrencode"
)

var (
	name   = flag.String("name", "", "The file base name to use as the ACL file name(e.g test.acl name is test)")
	encode = flag.Bool("encode", false, "Encode the CIDRs")
	search = flag.String("search", "", "Search for a IP in the CIDRs")
)

func main() {
	flag.Parse()
	if *encode {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", err)
		}
		str := string(stdin)
		cidrs := strings.Split(strings.TrimSuffix(str, "\n"), "\n")

		networks := []*net.IPNet{}
		for _, cidr := range cidrs {

			if strings.HasPrefix(cidr, "#") || strings.HasPrefix(cidr, "//") || cidr == "" {
				continue
			}

			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("Skipping invalid CIDR %s: %s", cidr, err)
				continue
			}
			networks = append(networks, network)
		}

		file, err := os.OpenFile(filepath.Clean(file(*name)), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("failed to open file: %s", err)
		}
		defer file.Close() // Make sure to close the file when the function returns

		cidrencode.Encode(file, networks)

	} else if *search != "" {
		file, err := os.OpenFile(filepath.Clean(file(*name)), os.O_RDONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open file: %s", err)
		}
		defer file.Close() // Make sure to close the file when the function returns

		ipAddress := net.ParseIP(*search)
		exists := cidrencode.Search(file, &ipAddress)
		log.Printf("Exists: %t", exists)
		if !exists {
			os.Exit(1)
		}
	}
}

func file(id string) string {
	return fmt.Sprintf("./%s.acl", id)
}

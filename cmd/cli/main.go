package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/jmoney/cidr-encoder/internal/cidrencode"
)

var (
	id     = flag.String("id", "", "ID to use for the generation")
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

		cidrencode.Encode(*id, networks)

	} else if *search != "" {
		exists := cidrencode.Search(*id, net.ParseIP(*search))
		log.Printf("Exists: %t", exists)
		if !exists {
			os.Exit(1)
		}
	}
}

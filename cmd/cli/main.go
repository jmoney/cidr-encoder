package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jmoney/cidr-encoder/internal/cidrencode"
	"github.com/projectdiscovery/mapcidr"
)

var (
	name   = flag.String("name", "", "The file base name to use as the ACL file name(e.g test.acl name is test).")
	encode = flag.Bool("encode", false, "Encode the CIDRs. Reads from STDIN.")
	search = flag.String("search", "", "Search for a IP in the CIDRs.")
	calc   = flag.Bool("calc", false, "Calculate the size of the encoded file. Reads from STDIN.")
)

func main() {
	flag.Parse()

	if *calc {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", err)
		}
		str := string(stdin)
		cidrs := strings.Split(strings.TrimSuffix(str, "\n"), "\n")
		min, max, estimatedSize := cidrencode.Calculate(convertStrToNetwork(cidrs))
		result := map[string]interface{}{
			"min":           mapcidr.Inet_ntoa(min),
			"max":           mapcidr.Inet_ntoa(max),
			"estimatedSize": estimatedSize,
			"humanReadable": cidrencode.BytesToHumanReadable(estimatedSize),
		}
		output, _ := json.Marshal(result)
		fmt.Println(string(output))
	} else if *encode {
		stdin, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read from stdin: %s", err)
		}
		str := string(stdin)
		cidrs := strings.Split(strings.TrimSuffix(str, "\n"), "\n")

		networks := convertStrToNetwork(cidrs)

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
		result := map[string]bool{
			ipAddress.String(): exists,
		}
		output, err := json.Marshal(result)
		if err != nil {
			log.Fatalf("failed to marshal result: %s", err)
		}
		fmt.Println(string(output))
		if !exists {
			os.Exit(1)
		}
	}
}

func convertStrToNetwork(cidrs []string) []*net.IPNet {
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
	return networks
}

func file(id string) string {
	return fmt.Sprintf("./%s.acl", id)
}

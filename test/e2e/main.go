package main

import (
	"encoding/json"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"

	"github.com/jmoney/cidr-encoder/internal/cidrencode"
	"github.com/projectdiscovery/mapcidr"
)

var (
	networks = []*net.IPNet{
		convertToCidr("10.1.0.0/16"),
		convertToCidr("10.2.1.3/24"),
		convertToCidr("3.4.2.4/22"),
		convertToCidr("52.23.164.188/32"),
	}

	elog = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)
)

func main() {
	os.Exit(test())
}

func test() int {
	testAcl, err := os.OpenFile(filepath.Clean("test.acl"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		elog.Fatalf("failed to open file: %s", err)
	}
	defer testAcl.Close()
	defer os.Remove(testAcl.Name())

	failed := make([]net.IP, 0)
	cidrencode.Encode(testAcl, networks)
	if err := testAcl.Sync(); err != nil {
		elog.Fatalf("failed to sync file: %s", err)
	}

	for i := 0; i < math.MaxUint32; i++ {
		ipAddress := mapcidr.Inet_ntoa(int64(i))
		check := checkIp(testAcl, ipAddress)
		if !check {
			failed = append(failed, ipAddress)
		}
	}

	if len(failed) > 0 {
		elog.Printf("Failed for %d ips\n", len(failed))
		str, _ := json.Marshal(failed)
		elog.Printf("Failed ips: %s\n", str)
	}

	return len(failed)
}

func checkIp(acl *os.File, ipAddress net.IP) bool {
	exists := cidrencode.Search(acl, ipAddress)

	containedNetworks := make([]*net.IPNet, 0)
	for _, network := range networks {
		if network.Contains(ipAddress) {
			containedNetworks = append(containedNetworks, network)
		}

		if len(containedNetworks) > 0 {
			if !exists {
				elog.Printf("IP %s does not exist in the database but should\n", ipAddress)
				return false
			}
		}
	}

	if exists && len(containedNetworks) == 0 {
		elog.Printf("IP %s exists in the database but should not\n", ipAddress)
		return false
	}

	return exists
}

func convertToCidr(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return network
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/jmoney/cidr-encoder/internal/cidrencode"
	"github.com/projectdiscovery/mapcidr"
)

var (
	memprof  = flag.String("memprofile", "", "write memory to profiles every 10s to this directory")
	interval = flag.Duration("interval", 10*time.Second, "interval to write memory profiles")
	elog     = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile)

	networks = []*net.IPNet{
		convertToCidr("10.1.0.0/16"),
		convertToCidr("10.2.1.3/24"),
		convertToCidr("3.4.2.4/22"),
		convertToCidr("52.23.164.188/32"),
	}
)

func logMemStats(memprof *string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	i := 0
	var mem runtime.MemStats
	for range ticker.C {
		if *memprof != "" {
			err := os.MkdirAll(*memprof, 0755)
			if err != nil {
				elog.Fatalln(err)
			}
			memProf, err := os.Create(fmt.Sprintf("%s/memprofile-%d.pprof", *memprof, i))
			if err != nil {
				elog.Fatalln(err)
			}

			runtime.GC()
			if err := pprof.WriteHeapProfile(memProf); err != nil {
				elog.Println(err)
			}
			memProf.Close()
		}

		runtime.ReadMemStats(&mem)
		memStats := map[string]string{
			"timestamp": time.Now().Format(time.RFC3339),
			"Alloc":     fmt.Sprintf("%v MiB", mem.Alloc/1024/1024),
			"Sys":       fmt.Sprintf("%v MiB", mem.Sys/1024/1024),
			"NumGC":     fmt.Sprintf("%v", mem.NumGC),
		}
		output, _ := json.Marshal(memStats)
		fmt.Printf("%s\n", output)
		i++
	}
}

func main() {
	flag.Parse()
	go logMemStats(memprof, *interval)
	os.Exit(test())
}

func test() int {
	testAcl, err := os.OpenFile(filepath.Clean("test.acl"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		elog.Fatalf("failed to open file: %s", err)
	}
	defer testAcl.Close()
	defer os.Remove(testAcl.Name())

	failed := make([]*net.IP, 0)
	cidrencode.Encode(testAcl, networks)
	if err := testAcl.Sync(); err != nil {
		elog.Fatalf("failed to sync file: %s", err)
	}

	var ipAddress net.IP
	for i := 0; i < math.MaxUint32; i++ {
		ipAddress = mapcidr.Inet_ntoa(int64(i))
		if !checkIp(testAcl, &ipAddress) {
			failed = append(failed, &ipAddress)
		}
	}

	if len(failed) > 0 {
		elog.Printf("Failed for %d ips\n", len(failed))
		str, _ := json.Marshal(failed)
		elog.Printf("Failed ips: %s\n", str)
	}

	return len(failed)
}

func checkIp(acl *os.File, ipAddress *net.IP) bool {
	exists := cidrencode.Search(acl, ipAddress)

	containedNetworks := make([]*net.IPNet, 0)
	for _, network := range networks {
		if network.Contains(*ipAddress) {
			containedNetworks = append(containedNetworks, network)
		}
	}

	if len(containedNetworks) > 0 {
		if !exists {
			elog.Printf("IP %s does not exist in the database but should\n", ipAddress)
			return false
		}
	} else if exists {
		elog.Printf("IP %s exists in the database but should not\n", ipAddress)
		return false
	}

	return true
}

func convertToCidr(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		elog.Fatalln(err)
	}
	return network
}

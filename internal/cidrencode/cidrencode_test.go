// bootstrap test for cidrencode package

package cidrencode

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/mapcidr"
)

func TestE2E_Full(t *testing.T) {
	networks := []*net.IPNet{
		convertToCidr("10.1.0.0/16"),
		convertToCidr("10.2.1.3/24"),
		convertToCidr("3.4.2.4/22"),
		convertToCidr("52.23.164.188/32"),
	}

	testAcl, err := os.OpenFile(filepath.Clean("test.acl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}

	Encode(testAcl, networks)

	t.Cleanup(func() {
		testAcl.Close() // Make sure to close the file when the function returns
		os.Remove(testAcl.Name())
	})

	for i := 0; i < math.MaxUint32; i++ {
		ipAddress := mapcidr.Inet_ntoa(int64(i))

		t.Run(fmt.Sprintf("TestE2E_%s", ipAddress), func(t *testing.T) {
			exists := Search(testAcl, ipAddress)
			contained := false
			for _, network := range networks {

				contained = contained || network.Contains(ipAddress)
				if network.Contains(ipAddress) {
					t.Logf("IP %s exists in the CIDR %s", ipAddress, network)
				}
			}

			if contained {
				if !exists {
					t.Errorf("IP %s does not exist in the database but should", ipAddress)
				}
			} else {
				if exists {
					t.Errorf("IP %s exists in the database but should not", ipAddress)
				}
			}
		})
	}
}

func convertToCidr(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return network
}

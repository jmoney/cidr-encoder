// bootstrap test for cidrencode package

package cidrencode

import (
	"math"
	"net"
	"os"
	"testing"

	"github.com/projectdiscovery/mapcidr"
)

func TestE2E_Full(t *testing.T) {
	cidrs := []string{
		"10.1.0.0/16",
		"10.2.1.3/24",
		"3.4.2.4/22",
		"52.23.164.188/32",
	}

	Encode("test", cidrs)

	t.Cleanup(func() {
		os.Remove("test.acl")
	})

	t.Run("TestE2E_Full", func(t *testing.T) {

		for i := 0; i < math.MaxUint32; i++ {
			ipAddress := mapcidr.Inet_ntoa(int64(i))
			exists := Search("test", ipAddress)

			contained := false
			for _, cidr := range cidrs {
				_, network, _ := net.ParseCIDR(cidr)
				t.Logf("Checking IP %s in CIDR %s", ipAddress, network)
				if network.Contains(ipAddress) {
					t.Logf("IP %s exists in the CIDR %s", ipAddress, network)
					if exists {
						t.Logf("IP %s exists in the database", ipAddress)
						contained = true
					}
				}
			}

			if !contained && exists {
				t.Errorf("IP %s exists in the database but should not", ipAddress)
			}
		}
	})
}

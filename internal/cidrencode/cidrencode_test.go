// bootstrap test for cidrencode package

package cidrencode

import (
	"fmt"
	"net"
	"os"
	"testing"
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

		for a := 0; a < 256; a++ {
			for b := 0; b < 256; b++ {
				for c := 0; c < 256; c++ {
					for d := 0; d < 256; d++ {
						ipAddress := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
						exists := Search("test", net.ParseIP(ipAddress))

						contained := false
						for _, cidr := range cidrs {
							_, network, _ := net.ParseCIDR(cidr)
							t.Logf("Checking IP %s in CIDR %s", ipAddress, network)
							if network.Contains(net.ParseIP(ipAddress)) {
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
				}
			}
		}
	})
}

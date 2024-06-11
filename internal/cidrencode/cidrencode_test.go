package cidrencode

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestExist(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	networks := []*net.IPNet{cidr}

	file, err := os.OpenFile(filepath.Clean("internal.acl"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %s", err)
	}
	Encode(file, networks)
	if err := file.Sync(); err != nil {
		t.Fatalf("failed to sync file: %s", err)
	}

	t.Run("TestExist", func(t *testing.T) {
		ip := net.ParseIP("10.0.0.0")
		if !Search(file, &ip) {
			t.Fatalf("failed to find ip in file")
		}
	})

	t.Run("TestNotExist", func(t *testing.T) {
		ip := net.ParseIP("8.8.8.8")
		if Search(file, &ip) {
			t.Fatalf("Found the ip in the file but should not have")
		}
	})
}

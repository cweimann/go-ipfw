//go:build freebsd

package ipfw

import (
	"strings"
	"testing"
)

func TestParseAddrsReader(t *testing.T) {
	in := `
# comment
192.0.2.1
198.51.100.0/24 7
# blank below

2001:db8::/32
`
	addrs, err := ParseAddrsReader(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 3 {
		t.Fatalf("len=%d want 3", len(addrs))
	}
	if addrs[1].Value != 7 || addrs[1].String() != "198.51.100.0/24 7" {
		t.Fatalf("addrs[1]=%q", addrs[1].String())
	}
}

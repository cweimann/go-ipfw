//go:build freebsd

package ipfw

import (
	"bytes"
	"net"
	"testing"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.1", "192.0.2.1"},
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.0/24 42", "192.0.2.0/24 42"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::/32", "2001:db8::/32"},
	}
	for _, tc := range cases {
		a, err := ParseAddr(tc.in)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", tc.in, err)
		}
		if got := a.String(); got != tc.want {
			t.Fatalf("ParseAddr(%q).String() = %q want %q", tc.in, got, tc.want)
		}
		te, err := a.toWire(1)
		if err != nil {
			t.Fatalf("toWire(%q): %v", tc.in, err)
		}
		round := addrFromWire(te)
		if round.String() != a.String() {
			t.Fatalf("roundtrip %q -> %q", a.String(), round.String())
		}
	}
}

func TestParseAddrIPv4Bytes(t *testing.T) {
	a, err := ParseAddr("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	te, err := a.toWire(1)
	if err != nil {
		t.Fatal(err)
	}
	subtype, masklen, _, key, _, _ := parseTEntryAddr(te)
	if subtype != AFInet || masklen != 32 {
		t.Fatalf("af/mask = %d/%d", subtype, masklen)
	}
	want := net.IPv4(203, 0, 113, 9).To4()
	if !bytes.Equal(key[:4], want) {
		t.Fatalf("addr bytes %v want %v", key[:4], want)
	}
}

func TestMarshalObjHeaderABI(t *testing.T) {
	oh := objHeader{Idx: 1, Set: 3, Type: TableAddr, Name: "t"}
	buf, err := marshalObjHeader(oh)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != objHeaderSize {
		t.Fatalf("len=%d", len(buf))
	}
	// Name always starts at ntlv+16 = 32
	if cstring(buf[32:32+tableNameSz]) != "t" {
		t.Fatalf("name=%q", cstring(buf[32:32+tableNameSz]))
	}
	switch currentABI() {
	case abi14:
		if le.Uint16(buf[12:14]) != 1 {
			t.Fatalf("abi14 header idx=%d", le.Uint16(buf[12:14]))
		}
		if buf[26] != 3 || buf[27] != TableAddr { // ntlv set/type at +10/+11 from ntlv@16
			t.Fatalf("abi14 ntlv set/type=%d/%d", buf[26], buf[27])
		}
	default:
		if le.Uint32(buf[8:12]) != 1 {
			t.Fatalf("abi15 header idx=%d", le.Uint32(buf[8:12]))
		}
		if buf[28] != 3 || buf[29] != TableAddr {
			t.Fatalf("abi15 ntlv set/type=%d/%d", buf[28], buf[29])
		}
	}
}

func TestDetectABI(t *testing.T) {
	a := currentABI()
	if a != abi14 && a != abi15 {
		t.Fatalf("unexpected abi %d", a)
	}
	t.Logf("running ABI %d", a)
}

//go:build freebsd

package ipfw

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

var errEmptyTableName = fmt.Errorf("empty table name")

// Addr is an ipfw addr-table key (host or network) with optional value.
type Addr struct {
	IP    net.IP
	Mask  int    // prefix length
	Value uint32 // legacy table value (0 if unused)
}

func (a Addr) String() string {
	s := a.IP.String()
	bits := a.Mask
	if bits < 0 {
		if a.IP.To4() != nil {
			bits = 32
		} else {
			bits = 128
		}
	}
	if a.IP.To4() != nil && bits != 32 || a.IP.To4() == nil && bits != 128 {
		s = fmt.Sprintf("%s/%d", s, bits)
	}
	if a.Value != 0 {
		return fmt.Sprintf("%s %d", s, a.Value)
	}
	return s
}

// ParseAddr parses an address or CIDR. An optional trailing value
// ("10.0.0.0/8 42") is accepted.
func ParseAddr(s string) (Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Addr{}, fmt.Errorf("empty address")
	}

	var value uint32
	fields := strings.Fields(s)
	key := fields[0]
	if len(fields) > 2 {
		return Addr{}, fmt.Errorf("parse %q: too many fields", s)
	}
	if len(fields) == 2 {
		v, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return Addr{}, fmt.Errorf("parse %q: bad value: %w", s, err)
		}
		value = uint32(v)
	}

	if strings.Contains(key, "/") {
		ip, ipnet, err := net.ParseCIDR(key)
		if err != nil {
			return Addr{}, fmt.Errorf("parse %q: %w", s, err)
		}
		ones, _ := ipnet.Mask.Size()
		return Addr{IP: ip.Mask(ipnet.Mask), Mask: ones, Value: value}, nil
	}

	ip := net.ParseIP(key)
	if ip == nil {
		return Addr{}, fmt.Errorf("parse %q: invalid address", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return Addr{IP: v4, Mask: 32, Value: value}, nil
	}
	return Addr{IP: ip.To16(), Mask: 128, Value: value}, nil
}

func (a Addr) toWire(idx uint32) ([]byte, error) {
	var (
		subtype uint8
		mask    int
		key     []byte
	)
	if v4 := a.IP.To4(); v4 != nil {
		subtype = AFInet
		key = append([]byte(nil), v4...)
		mask = a.Mask
		if mask < 0 {
			mask = 32
		}
		if mask > 32 {
			return nil, fmt.Errorf("IPv4 prefix length %d out of range", mask)
		}
	} else {
		v6 := a.IP.To16()
		if v6 == nil {
			return nil, fmt.Errorf("invalid IP")
		}
		subtype = AFInet6
		key = append([]byte(nil), v6...)
		mask = a.Mask
		if mask < 0 {
			mask = 128
		}
		if mask > 128 {
			return nil, fmt.Errorf("IPv6 prefix length %d out of range", mask)
		}
	}
	return marshalTEntry(idx, subtype, uint8(mask), key, a.Value), nil
}

func addrFromWire(b []byte) Addr {
	subtype, masklen, _, key, value, _ := parseTEntryAddr(b)
	a := Addr{Mask: int(masklen), Value: value}
	switch subtype {
	case AFInet:
		ip := make(net.IP, 4)
		copy(ip, key[:4])
		a.IP = ip
	case AFInet6:
		ip := make(net.IP, 16)
		copy(ip, key[:16])
		a.IP = ip
	}
	return a
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func tableTypeName(t uint8) string {
	switch t {
	case TableAddr:
		return "addr"
	case TableInterface:
		return "iface"
	case TableNumber:
		return "number"
	case TableFlow:
		return "flow"
	case TableMAC:
		return "mac"
	default:
		return fmt.Sprintf("type%d", t)
	}
}

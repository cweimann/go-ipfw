//go:build freebsd

package ipfw

import (
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// IP_FW3 table sockopt layouts changed in FreeBSD 15 (32-bit named-object
// indexes / rule numbers). FreeBSD 14.x still uses the pre-15 field packing.
// Detect once from kern.osrelease and marshal accordingly.

type abiKind int

const (
	abi14 abiKind = 14 // FreeBSD < 15
	abi15 abiKind = 15 // FreeBSD >= 15
)

var (
	abiOnce sync.Once
	abiCur  abiKind = abi15
)

func currentABI() abiKind {
	abiOnce.Do(func() {
		abiCur = detectABI()
	})
	return abiCur
}

func detectABI() abiKind {
	rel, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return abi15
	}
	majorStr, _, _ := strings.Cut(rel, ".")
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return abi15
	}
	if major < 15 {
		return abi14
	}
	return abi15
}

// opVersion returns the IP_FW3 opheader.version that ipfw(8) uses for opcode.
// On FreeBSD 14, most table management ops leave version 0; entry add/del/list
// set version 1. FreeBSD 15 always uses IP_FW3_OPVER (1).
func opVersion(opcode uint16) uint16 {
	if currentABI() == abi15 {
		return ipFW3OpVer
	}
	switch opcode {
	case opTableXAdd, opTableXDel, opTableXList, opTableXFind:
		return 1
	default:
		return 0
	}
}

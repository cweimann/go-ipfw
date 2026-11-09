//go:build freebsd

package ipfw

import (
	"fmt"
	"syscall"
	"unsafe"
)

func (h *Handle) set3(opcode uint16, buf []byte) error {
	if len(buf) < opHeaderSize {
		return fmt.Errorf("IP_FW3 set buffer too small")
	}
	le.PutUint16(buf[0:2], opcode)
	le.PutUint16(buf[2:4], opVersion(opcode))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(h.fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(ipFW3),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt IP_FW3 op %d: %w", opcode, errno)
	}
	return nil
}

// get3 issues getsockopt(IP_FW3). buf must be large enough; on return
// n is the kernel-reported length (may be less than len(buf)).
func (h *Handle) get3(opcode uint16, buf []byte) (n int, err error) {
	if len(buf) < opHeaderSize {
		return 0, fmt.Errorf("IP_FW3 get buffer too small")
	}
	le.PutUint16(buf[0:2], opcode)
	le.PutUint16(buf[2:4], opVersion(opcode))
	lenVal := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(h.fd),
		uintptr(syscall.IPPROTO_IP),
		uintptr(ipFW3),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&lenVal)),
		0,
	)
	if errno != 0 {
		return int(lenVal), fmt.Errorf("getsockopt IP_FW3 op %d: %w", opcode, errno)
	}
	return int(lenVal), nil
}

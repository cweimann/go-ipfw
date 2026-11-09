//go:build freebsd

package ipfw

import (
	"fmt"
	"syscall"
)

// Handle is an open raw IP socket used for IP_FW3 sockopts.
type Handle struct {
	fd int
}

// Open creates a raw IP socket for ipfw control. Requires root (or
// appropriate privilege to create SOCK_RAW).
func Open() (*Handle, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("socket AF_INET/SOCK_RAW: %w", err)
	}
	return &Handle{fd: fd}, nil
}

// Close closes the control socket.
func (h *Handle) Close() error {
	if h == nil || h.fd < 0 {
		return nil
	}
	err := syscall.Close(h.fd)
	h.fd = -1
	return err
}

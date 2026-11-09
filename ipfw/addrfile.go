//go:build freebsd

package ipfw

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseAddrsReader reads addresses from r: one IP/CIDR [value] per line.
// Blank lines and #-comments are ignored.
func ParseAddrsReader(r io.Reader) ([]Addr, error) {
	var out []Addr
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		a, err := ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ParseAddrsFile reads addresses from path (see ParseAddrsReader).
func ParseAddrsFile(path string) ([]Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	addrs, err := ParseAddrsReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return addrs, nil
}

// SetAddrsFile replaces the contents of table with addresses from path.
func (h *Handle) SetAddrsFile(table, path string) (added, deleted int, err error) {
	addrs, err := ParseAddrsFile(path)
	if err != nil {
		return 0, 0, err
	}
	return h.SetAddrs(table, addrs)
}

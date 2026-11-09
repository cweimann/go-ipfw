//go:build freebsd

package ipfw

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Table describes an ipfw lookup table.
type Table struct {
	Name   string
	Set    uint32
	Type   uint8
	Flags  uint16
	Count  uint32
	Limit  uint32
	Refcnt uint32
	VMask  uint32
	Algo   string
}

// TypeName returns the table type as used by ipfw(8) (addr, iface, …).
func (t Table) TypeName() string { return tableTypeName(t.Type) }

func (h *Handle) objHeaderFor(name string, set uint8) (objHeader, error) {
	return objHeader{Idx: 1, Set: set, Name: name}, nil
}

// ListTables returns all ipfw tables.
func (h *Handle) ListTables() ([]Table, error) {
	sz := objLHeaderSize + 16*xtableInfoSize
	for {
		buf := make([]byte, sz)
		le.PutUint32(buf[16:20], uint32(sz)) // objLHeader.Size
		n, err := h.get3(opTablesXList, buf)
		if err != nil {
			if errno, ok := underlyingErrno(err); ok && errno == syscall.ENOMEM {
				need := int(le.Uint32(buf[16:20]))
				if need <= sz {
					need = sz * 2
				}
				sz = need
				continue
			}
			return nil, err
		}
		if n < objLHeaderSize {
			return nil, fmt.Errorf("IP_FW_TABLES_XLIST: short reply %d", n)
		}
		count := le.Uint32(buf[12:16])
		objSize := int(le.Uint32(buf[20:24]))
		if objSize < xtableInfoSize {
			objSize = xtableInfoSize
		}
		out := make([]Table, 0, count)
		off := objLHeaderSize
		for i := uint32(0); i < count; i++ {
			if off+xtableInfoSize > len(buf) {
				break
			}
			out = append(out, tableFromInfoBytes(buf[off:off+xtableInfoSize]))
			off += objSize
		}
		return out, nil
	}
}

func tableFromInfoBytes(b []byte) Table {
	info := (*xtableInfo)(unsafe.Pointer(&b[0]))
	return Table{
		Name:   cstring(info.Tablename[:]),
		Set:    info.Set,
		Type:   info.Type,
		Flags:  info.Flags,
		Count:  info.Count,
		Limit:  info.Limit,
		Refcnt: info.Refcnt,
		VMask:  info.VMask,
		Algo:   cstring(info.Algoname[:]),
	}
}

// TableInfo returns details for one table.
func (h *Handle) TableInfo(name string) (Table, error) {
	return h.TableInfoSet(name, 0)
}

// TableInfoSet returns details for a table in a specific set.
func (h *Handle) TableInfoSet(name string, set uint8) (Table, error) {
	oh, err := h.objHeaderFor(name, set)
	if err != nil {
		return Table{}, err
	}
	hdr, err := marshalObjHeader(oh)
	if err != nil {
		return Table{}, err
	}
	buf := make([]byte, objHeaderSize+xtableInfoSize)
	copy(buf, hdr)
	n, err := h.get3(opTableXInfo, buf)
	if err != nil {
		return Table{}, err
	}
	if n < objHeaderSize+xtableInfoSize {
		return Table{}, fmt.Errorf("IP_FW_TABLE_XINFO: short reply %d", n)
	}
	return tableFromInfoBytes(buf[objHeaderSize : objHeaderSize+xtableInfoSize]), nil
}

// AddTable creates an addr table (default type) in set 0.
func (h *Handle) AddTable(name string) error {
	return h.AddTableOpts(name, TableOpts{Type: TableAddr, VMask: VTypeLegacy})
}

// TableOpts controls table creation.
type TableOpts struct {
	Type   uint8
	Set    uint8
	VMask  uint32
	Limit  uint32
	Algo   string
	Locked bool
}

// AddTableOpts creates a table with the given options.
func (h *Handle) AddTableOpts(name string, opts TableOpts) error {
	if opts.Type == 0 {
		opts.Type = TableAddr
	}
	if opts.VMask == 0 {
		opts.VMask = VTypeLegacy
	}
	oh, err := h.objHeaderFor(name, opts.Set)
	if err != nil {
		return err
	}
	hdr, err := marshalObjHeader(oh)
	if err != nil {
		return err
	}

	var info xtableInfo
	info.Type = opts.Type
	info.VMask = opts.VMask
	info.Set = uint32(opts.Set)
	info.Limit = opts.Limit
	if opts.Locked {
		info.Flags = TGFlagLocked
	}
	copy(info.Tablename[:], name)
	if opts.Algo != "" {
		if len(opts.Algo) >= algoNameSz {
			return fmt.Errorf("algo name %q too long", opts.Algo)
		}
		copy(info.Algoname[:], opts.Algo)
	}

	buf := make([]byte, objHeaderSize+xtableInfoSize)
	copy(buf, hdr)
	infoBytes := (*[xtableInfoSize]byte)(unsafe.Pointer(&info))[:]
	copy(buf[objHeaderSize:], infoBytes)
	return h.set3(opTableXCreate, buf)
}

// DeleteTable destroys a table in set 0.
func (h *Handle) DeleteTable(name string) error {
	return h.DeleteTableSet(name, 0)
}

// DeleteTableSet destroys a table in the given set.
func (h *Handle) DeleteTableSet(name string, set uint8) error {
	oh, err := h.objHeaderFor(name, set)
	if err != nil {
		return err
	}
	buf, err := marshalObjHeader(oh)
	if err != nil {
		return err
	}
	return h.set3(opTableXDestroy, buf)
}

// ClearAddrs flushes all entries from a table (ipfw table NAME flush).
func (h *Handle) ClearAddrs(name string) error {
	return h.ClearAddrsSet(name, 0)
}

// ClearAddrsSet flushes a table in the given set.
func (h *Handle) ClearAddrsSet(name string, set uint8) error {
	oh, err := h.objHeaderFor(name, set)
	if err != nil {
		return err
	}
	buf, err := marshalObjHeader(oh)
	if err != nil {
		return err
	}
	return h.set3(opTableXFlush, buf)
}

// ListAddrs returns all address entries in an addr table.
func (h *Handle) ListAddrs(name string) ([]Addr, error) {
	return h.ListAddrsSet(name, 0)
}

// ListAddrsSet returns entries for a table in the given set.
func (h *Handle) ListAddrsSet(name string, set uint8) ([]Addr, error) {
	info, err := h.TableInfoSet(name, set)
	if err != nil {
		return nil, err
	}
	if info.Type != TableAddr {
		return nil, fmt.Errorf("table %q is type %s, not addr", name, info.TypeName())
	}

	sz := int(info.Count)*objTEntrySize + objHeaderSize + xtableInfoSize + 64
	if sz < objHeaderSize+xtableInfoSize+objTEntrySize {
		sz = objHeaderSize + xtableInfoSize + 64
	}

	for tries := 0; tries < 8; tries++ {
		oh, err := h.objHeaderFor(name, set)
		if err != nil {
			return nil, err
		}
		hdr, err := marshalObjHeader(oh)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, sz)
		copy(buf, hdr)
		n, err := h.get3(opTableXList, buf)
		if err != nil {
			if errno, ok := underlyingErrno(err); ok && errno == syscall.ENOMEM {
				sz *= 2
				continue
			}
			return nil, err
		}
		if n < objHeaderSize+xtableInfoSize {
			return nil, fmt.Errorf("IP_FW_TABLE_XLIST: short reply %d", n)
		}
		xi := (*xtableInfo)(unsafe.Pointer(&buf[objHeaderSize]))
		count := int(xi.Count)
		off := objHeaderSize + xtableInfoSize
		out := make([]Addr, 0, count)
		for i := 0; i < count; i++ {
			if off+objTEntrySize > n {
				break
			}
			_, _, _, _, _, elen := parseTEntryAddr(buf[off:])
			out = append(out, addrFromWire(buf[off:]))
			off += elen
		}
		return out, nil
	}
	return nil, fmt.Errorf("IP_FW_TABLE_XLIST: buffer too small after retries")
}

// AddAddrs adds addresses to a table. Returns how many were newly added
// (duplicates that already existed are not counted as added).
func (h *Handle) AddAddrs(name string, addrs []Addr) (added int, err error) {
	return h.mutateAddrs(opTableXAdd, name, 0, addrs, false)
}

// DeleteAddrs removes addresses from a table.
func (h *Handle) DeleteAddrs(name string, addrs []Addr) (deleted int, err error) {
	return h.mutateAddrs(opTableXDel, name, 0, addrs, false)
}

// SetAddrs replaces table contents: flush, then add. Not atomic across
// the flush/add boundary (ipfw has no single replace sockopt).
func (h *Handle) SetAddrs(name string, addrs []Addr) (added, deleted int, err error) {
	before, err := h.ListAddrs(name)
	if err != nil {
		before = nil
	}
	if err := h.ClearAddrs(name); err != nil {
		return 0, 0, err
	}
	deleted = len(before)
	if len(addrs) == 0 {
		return 0, deleted, nil
	}
	added, err = h.AddAddrs(name, addrs)
	return added, deleted, err
}

func (h *Handle) mutateAddrs(opcode uint16, name string, set uint8, addrs []Addr, atomic bool) (int, error) {
	if len(addrs) == 0 {
		return 0, nil
	}
	oh, err := h.objHeaderFor(name, set)
	if err != nil {
		return 0, err
	}
	oh.Type = TableAddr
	hdr, err := marshalObjHeader(oh)
	if err != nil {
		return 0, err
	}

	ctlvLen := objCTLVSize + objTEntrySize*len(addrs)
	buf := make([]byte, objHeaderSize+ctlvLen)
	copy(buf, hdr)

	// ctlv header
	off := objHeaderSize
	le.PutUint32(buf[off+4:off+8], uint32(ctlvLen)) // length
	le.PutUint32(buf[off+8:off+12], uint32(len(addrs)))
	if atomic {
		buf[off+15] = ctfAtomic
	}
	off += objCTLVSize
	for _, a := range addrs {
		te, err := a.toWire(oh.Idx)
		if err != nil {
			return 0, err
		}
		copy(buf[off:], te)
		off += objTEntrySize
	}

	_, err = h.get3(opcode, buf)
	changed := 0
	off = objHeaderSize + objCTLVSize
	for i := 0; i < len(addrs); i++ {
		if off+objTEntrySize > len(buf) {
			break
		}
		_, _, result, _, _, elen := parseTEntryAddr(buf[off:])
		switch result {
		case TRAdded, TRDeleted, TRUpdated:
			changed++
		}
		off += elen
	}

	if err != nil {
		if errno, ok := underlyingErrno(err); ok {
			if opcode == opTableXAdd && errno == syscall.EEXIST {
				return changed, nil
			}
			if opcode == opTableXDel && errno == syscall.ENOENT {
				return changed, nil
			}
		}
		return changed, err
	}
	return changed, nil
}

func underlyingErrno(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno, true
	}
	return 0, false
}

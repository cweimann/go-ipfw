//go:build freebsd

package ipfw

import (
	"encoding/binary"
	"fmt"
)

// Constants matching FreeBSD <netinet/ip_fw.h> for IP_FW3 table sockopts.
// Struct *sizes* are stable across FreeBSD 14.2 and 15.1; some field
// packings inside obj_header / obj_ntlv / table_value changed in 15.
// See abi.go and aiscripts/ipfw_sockopt_sizes.c.

const (
	ipFW3       = 48 // IPPROTO_IP sockopt
	ipFW3OpVer  = 1
	tableNameSz = 64
	algoNameSz  = 64
	keySize     = 40 // sizeof union k in ipfw_obj_tentry (tflow_entry)
	valueSize   = 64 // sizeof(ipfw_table_value)

	opHeaderSize   = 8
	objTLVSize     = 8
	objNTLVSize    = 80
	objHeaderSize  = 96
	objLHeaderSize = 24
	objCTLVSize    = 16
	objTEntrySize  = 120
	xtableInfoSize = 200
	taTInfoSize    = 32
)

// Address families (from <sys/socket.h>).
const (
	AFInet  = 2
	AFInet6 = 28
)

// IP_FW3 table opcodes.
const (
	opTableXAdd     = 86
	opTableXDel     = 87
	opTableXList    = 89
	opTableXDestroy = 90
	opTablesXList   = 92
	opTableXInfo    = 93
	opTableXFlush   = 94
	opTableXCreate  = 95
	opTableXModify  = 96
	opTableXFind    = 106
	opTableXSwap    = 109
)

// Table types (IPFW_TABLE_*).
const (
	TableAddr      = 1
	TableInterface = 2
	TableNumber    = 3
	TableFlow      = 4
	TableMAC       = 5
)

// TLV types.
const (
	tlvTblName = 1
)

// Containter / entry flags.
const (
	tfUpdate  = 0x01 // IPFW_TF_UPDATE
	ctfAtomic = 0x01 // IPFW_CTF_ATOMIC
)

// Table generic flags.
const (
	TGFlagLocked = 0x01
)

// Modification flags.
const (
	TMFlagLimit = 0x0002
	TMFlagLock  = 0x0004
)

// Legacy value type: all value fields filled from one number.
const VTypeLegacy = 0xffffffff

// Operation results on ipfw_obj_tentry.result.
const (
	TRIgnored  = 0
	TRAdded    = 1
	TRUpdated  = 2
	TRDeleted  = 3
	TRLimit    = 4
	TRNotFound = 5
	TRExists   = 6
	TRError    = 7
)

var le = binary.LittleEndian

// objHeader is the logical form of ipfw_obj_header (marshaled per-ABI).
type objHeader struct {
	Idx  uint32
	Set  uint8
	Type uint8 // ntlv.type (table type when set)
	Name string
}

// objLHeader is ipfw_obj_lheader (layout identical on 14/15).
type objLHeader struct {
	OpHeader [opHeaderSize]byte
	SetMask  uint32
	Count    uint32
	Size     uint32
	ObjSize  uint32
}

// objCTLV is ipfw_obj_ctlv (layout identical on 14/15).
type objCTLV struct {
	Type    uint16
	Flags   uint16
	Length  uint32
	Count   uint32
	ObjSize uint16
	Version uint8
	CFlags  uint8
}

// xtableInfo is ipfw_xtable_info (layout identical on 14/15).
type xtableInfo struct {
	Type      uint8
	TFlags    uint8
	MFlags    uint16
	Flags     uint16
	Spare     [3]uint16
	VMask     uint32
	Set       uint32
	Kidx      uint32
	Refcnt    uint32
	Count     uint32
	Size      uint32
	Limit     uint32
	Tablename [tableNameSz]byte
	Algoname  [algoNameSz]byte
	TAInfo    [taTInfoSize]byte
}

// marshalObjHeader writes ipfw_obj_header for the running FreeBSD ABI.
func marshalObjHeader(oh objHeader) ([]byte, error) {
	if len(oh.Name) == 0 {
		return nil, errEmptyTableName
	}
	if len(oh.Name) >= tableNameSz {
		return nil, fmt.Errorf("table name %q too long (max %d)", oh.Name, tableNameSz-1)
	}
	buf := make([]byte, objHeaderSize)
	// bytes 0..7: opheader left zero; set3/get3 fill opcode/version

	ntlvOff := 16
	switch currentABI() {
	case abi14:
		// uint32 spare; uint16 idx; uint8 objtype; uint8 objsubtype
		le.PutUint16(buf[12:14], uint16(oh.Idx))
		// ntlv: uint16 idx; uint8 set; uint8 type; uint32 spare; name[64]
		le.PutUint16(buf[ntlvOff:ntlvOff+2], tlvTblName)       // head.type
		le.PutUint32(buf[ntlvOff+4:ntlvOff+8], objNTLVSize)     // head.length
		le.PutUint16(buf[ntlvOff+8:ntlvOff+10], uint16(oh.Idx)) // ntlv.idx
		buf[ntlvOff+10] = oh.Set
		buf[ntlvOff+11] = oh.Type
		copy(buf[ntlvOff+16:ntlvOff+16+tableNameSz], oh.Name)
	default: // abi15
		// uint32 idx; uint16 spare; uint8 objtype; uint8 objsubtype
		le.PutUint32(buf[8:12], oh.Idx)
		// ntlv: uint32 idx; uint8 set; uint8 type; uint16 spare; name[64]
		le.PutUint16(buf[ntlvOff:ntlvOff+2], tlvTblName)
		le.PutUint32(buf[ntlvOff+4:ntlvOff+8], objNTLVSize)
		le.PutUint32(buf[ntlvOff+8:ntlvOff+12], oh.Idx)
		buf[ntlvOff+12] = oh.Set
		buf[ntlvOff+13] = oh.Type
		copy(buf[ntlvOff+16:ntlvOff+16+tableNameSz], oh.Name)
	}
	return buf, nil
}

// marshalTEntry writes one ipfw_obj_tentry for an addr-table key.
func marshalTEntry(idx uint32, subtype, masklen uint8, key []byte, value uint32) []byte {
	buf := make([]byte, objTEntrySize)
	le.PutUint32(buf[4:8], objTEntrySize) // head.length
	buf[8] = subtype
	buf[9] = masklen
	// idx: uint32 on 15; uint16+spare on 14 — little-endian 1 is identical
	le.PutUint32(buf[12:16], idx)
	copy(buf[16:16+keySize], key)
	putLegacyValue(buf[56:56+valueSize], value)
	return buf
}

// putLegacyValue writes ipfw_table_value for IPFW_VTYPE_LEGACY.
func putLegacyValue(dst []byte, val uint32) {
	if len(dst) < valueSize {
		return
	}
	// Zero first; then fill per-ABI field layout (set_legacy_value in ipfw).
	for i := range dst {
		dst[i] = 0
	}
	switch currentABI() {
	case abi14:
		// tag u32, pipe u32, divert u16, skipto u16, netgraph u32,
		// fib u32, nat u32, nh4 u32, dscp u8, spare0 u8, kidx u16, …
		le.PutUint32(dst[0:4], val)   // tag
		le.PutUint32(dst[4:8], val)   // pipe
		le.PutUint16(dst[8:10], uint16(val))  // divert
		le.PutUint16(dst[10:12], uint16(val)) // skipto
		le.PutUint32(dst[12:16], val) // netgraph
		le.PutUint32(dst[16:20], val) // fib
		le.PutUint32(dst[20:24], val) // nat
		le.PutUint32(dst[24:28], val) // nh4
		dst[28] = uint8(val)          // dscp
		// kidx at 30 is left 0
		le.PutUint32(dst[48:52], val) // limit (after nh6 at 32..48)
	default:
		// tag u32, pipe u16, divert u16, skipto u32, netgraph u32,
		// nat u32, nh4 u32, fib u16, dscp u8, spare0 u8, kidx u32, …
		le.PutUint32(dst[0:4], val)             // tag
		le.PutUint16(dst[4:6], uint16(val))     // pipe
		le.PutUint16(dst[6:8], uint16(val))     // divert
		le.PutUint32(dst[8:12], val)            // skipto
		le.PutUint32(dst[12:16], val)           // netgraph
		le.PutUint32(dst[16:20], val)           // nat
		le.PutUint32(dst[20:24], val)           // nh4
		le.PutUint16(dst[24:26], uint16(val))   // fib
		dst[26] = uint8(val)                    // dscp
		le.PutUint32(dst[48:52], val)           // limit
		le.PutUint32(dst[56:60], val)           // mark
	}
}

// parseTEntryAddr reads subtype/mask/key/tag from a wire ipfw_obj_tentry.
// Those fields share offsets on FreeBSD 14 and 15.
func parseTEntryAddr(b []byte) (subtype, masklen, result uint8, key []byte, value uint32, length int) {
	if len(b) < objTEntrySize {
		return 0, 0, 0, nil, 0, len(b)
	}
	length = int(le.Uint32(b[4:8]))
	if length < objTEntrySize {
		length = objTEntrySize
	}
	subtype = b[8]
	masklen = b[9]
	result = b[10]
	key = append([]byte(nil), b[16:16+16]...) // enough for v4/v6
	value = le.Uint32(b[56:60])               // tag
	return
}

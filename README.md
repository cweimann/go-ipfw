# go-ipfw

Go library and CLI to control [ipfw](https://man.freebsd.org/cgi/man.cgi?query=ipfw&sektion=8) on FreeBSD through `IP_FW3` sockopts. The CLI is mostly to demonstrate usage since you should be able to use ipfw from the command line.

The main goal is table management (list / add / delete addresses) without shelling out to `ipfw`. Broader opcode coverage can grow over time.

Requires FreeBSD 14.2 or 15.1 (IP_FW3 table ABI differences are handled at runtime). Needs Go 1.21+. Needs root (raw `IPPROTO_RAW` socket). The `ipfw` kernel module must be loaded.

## Library

```go
package main

import (
	"fmt"
	"log"

	"k12usa.com/go-ipfw/ipfw"
)

func main() {
	h, err := ipfw.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	tables, err := h.ListTables()
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range tables {
		fmt.Println(t.Name)
	}

	addr, _ := ipfw.ParseAddr("203.0.113.10")
	if _, err := h.AddAddrs("blockedsites", []ipfw.Addr{addr}); err != nil {
		log.Fatal(err)
	}
}
```

Useful methods on `*ipfw.Handle`:

| Method | Opcode |
| --- | --- |
| `ListTables` | `IP_FW_TABLES_XLIST` |
| `TableInfo` | `IP_FW_TABLE_XINFO` |
| `AddTable` / `AddTableOpts` | `IP_FW_TABLE_XCREATE` |
| `DeleteTable` | `IP_FW_TABLE_XDESTROY` |
| `ListAddrs` | `IP_FW_TABLE_XLIST` |
| `AddAddrs` | `IP_FW_TABLE_XADD` |
| `DeleteAddrs` | `IP_FW_TABLE_XDEL` |
| `ClearAddrs` | `IP_FW_TABLE_XFLUSH` |
| `SetAddrs` | flush + add (no single replace opcode) |

## CLI

```sh
go install k12usa.com/go-ipfw/cmd/goipfw@latest   # or: go build -o goipfw ./cmd/goipfw

goipfw tables
goipfw table NAME                 # list addresses
goipfw table NAME info
goipfw table NAME create
goipfw table NAME destroy
goipfw table NAME add ADDR...
goipfw table NAME delete ADDR...
goipfw table NAME clear
goipfw table NAME replace [ADDR...]
goipfw table NAME replace -f FILE
goipfw table NAME load FILE
```

`ADDR` is an IP or CIDR, optionally followed by a numeric value (`203.0.113.10 42`).

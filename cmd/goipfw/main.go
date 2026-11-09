// Command goipfw is a small FreeBSD ipfw table management CLI.
package main

import (
	"fmt"
	"os"
	"strings"

	"k12usa.com/go-ipfw/ipfw"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	h, err := ipfw.Open()
	if err != nil {
		fatal(err)
	}
	defer h.Close()

	switch os.Args[1] {
	case "tables":
		cmdTables(h)
	case "table":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		cmdTable(h, os.Args[2], os.Args[3:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func cmdTables(h *ipfw.Handle) {
	tables, err := h.ListTables()
	if err != nil {
		fatal(err)
	}
	for _, t := range tables {
		fmt.Printf("%s\ttype=%s set=%d count=%d\n", t.Name, t.TypeName(), t.Set, t.Count)
	}
}

func cmdTable(h *ipfw.Handle, name string, args []string) {
	if len(args) == 0 {
		listAddrs(h, name)
		return
	}
	switch args[0] {
	case "show", "list":
		listAddrs(h, name)
	case "info":
		info, err := h.TableInfo(name)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("name=%s type=%s set=%d count=%d limit=%d refcnt=%d algo=%s\n",
			info.Name, info.TypeName(), info.Set, info.Count, info.Limit, info.Refcnt, info.Algo)
	case "add":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: goipfw table NAME add ADDR..."))
		}
		addrs, err := parseAddrs(args[1:])
		if err != nil {
			fatal(err)
		}
		n, err := h.AddAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d\n", n)
	case "delete", "del", "remove", "rm":
		if len(args) < 2 {
			fatal(fmt.Errorf("usage: goipfw table NAME delete ADDR..."))
		}
		addrs, err := parseAddrs(args[1:])
		if err != nil {
			fatal(err)
		}
		n, err := h.DeleteAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("deleted %d\n", n)
	case "clear", "flush":
		if err := h.ClearAddrs(name); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	case "replace", "set":
		addrs, err := addrsFromArgs(args[1:])
		if err != nil {
			fatal(err)
		}
		a, d, err := h.SetAddrs(name, addrs)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d deleted %d\n", a, d)
	case "load":
		if len(args) != 2 {
			fatal(fmt.Errorf("usage: goipfw table NAME load FILE"))
		}
		a, d, err := h.SetAddrsFile(name, args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Printf("added %d deleted %d\n", a, d)
	case "create":
		if err := h.AddTable(name); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	case "destroy":
		if err := h.DeleteTable(name); err != nil {
			fatal(err)
		}
		fmt.Println("ok")
	default:
		fatal(fmt.Errorf("unknown table subcommand %q", args[0]))
	}
}

func listAddrs(h *ipfw.Handle, name string) {
	addrs, err := h.ListAddrs(name)
	if err != nil {
		fatal(err)
	}
	for _, a := range addrs {
		fmt.Println(a.String())
	}
}

func parseAddrs(args []string) ([]ipfw.Addr, error) {
	out := make([]ipfw.Addr, 0, len(args))
	for i := 0; i < len(args); i++ {
		s := args[i]
		// Allow "ADDR VALUE" as two argv words, like ipfw(8).
		if i+1 < len(args) && looksLikeValue(args[i+1]) && !strings.Contains(s, " ") {
			s = s + " " + args[i+1]
			i++
		}
		for _, part := range splitAddrTokens(s) {
			a, err := ipfw.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
	}
	return out, nil
}

func looksLikeValue(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func splitAddrTokens(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Already "addr value" as one string.
	fields := strings.Fields(s)
	if len(fields) == 2 && looksLikeValue(fields[1]) {
		return []string{s}
	}
	return fields
}

// addrsFromArgs accepts either ADDR... or -f FILE (FILE may be "-" for stdin).
func addrsFromArgs(args []string) ([]ipfw.Addr, error) {
	if len(args) >= 1 && (args[0] == "-f" || args[0] == "--file") {
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: replace -f FILE")
		}
		if args[1] == "-" {
			return ipfw.ParseAddrsReader(os.Stdin)
		}
		return ipfw.ParseAddrsFile(args[1])
	}
	return parseAddrs(args)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  goipfw tables
  goipfw table NAME [show]
  goipfw table NAME info
  goipfw table NAME create
  goipfw table NAME destroy
  goipfw table NAME add ADDR...
  goipfw table NAME delete ADDR...
  goipfw table NAME clear
  goipfw table NAME replace [ADDR...]
  goipfw table NAME replace -f FILE
  goipfw table NAME load FILE    # same as replace -f FILE

ADDR may be an IP or CIDR, optionally followed by a numeric value.
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "goipfw: %v\n", err)
	os.Exit(1)
}

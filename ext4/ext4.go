package main

import (
	"fmt"
	"io"
	"os"
)

func printUsage(w io.Writer, name string) {
	fmt.Fprintf(w, "Usage: %s [enable|disable] <device> [--force]\n\n", name)
	fmt.Fprintln(w, "Enable or disable encryption on an ext4 filesystem.")
	fmt.Fprintln(w, "  <device> - Path to the filesystem device")
	fmt.Fprintln(w, "  --force  - Automatically proceed with the operation")
}

func main() {
	if len(os.Args) != 3 {
		printUsage(os.Stderr, os.Args[0])
		os.Exit(1)
	}
	switch os.Args[1] {
	case "enable":
		fmt.Println("Enabling encryption!!")
	case "disable":
		fmt.Println("Disabling encryption!!")
	default:
		fmt.Fprintf(os.Stderr, "%s: invalid command %q\n", os.Args[0], os.Args[1])
		printUsage(os.Stderr, os.Args[0])
		os.Exit(1)
	}

	if isExt4EncryptionEnabled(os.Args[2]) {
		fmt.Printf("%q has encryption\n", os.Args[2])
	} else {
		fmt.Printf("%q doesn't have encryption\n", os.Args[2])
	}
}

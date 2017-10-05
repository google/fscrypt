package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

var (
	// Setup command parsing
	cmdName = os.Args[0]
	set     = flag.NewFlagSet(cmdName, flag.ContinueOnError)
	// Flags for our command
	forceFlag   = set.Bool("force", false, "Suppress all warnings and do not prompt")
	versionFlag = set.Bool("version", false, "Print the fscrypt version.")
	helpFlag    = set.Bool("help", false, "Print this help text.")
	// fscrypt's version (set by Makefile)
	version string
)

const (
	manPage  = "fscrypt-ext4(8)"
	manBrief = "enable or disable encryption on an ext4 filesystem"
	usageFmt = `
Usage:
	%[1]s [enable | disable] <mountpoint> [--force]
	%[1]s --help
	%[1]s --version

Arguments:
  	<mountpoint> - path to an ext4 filesystem
`
)

func printUsageAndExit(err error) {
	var w io.Writer
	var rc int
	if err == nil {
		w = os.Stdout
		rc = 0
		fmt.Fprintf(w, "%s - %s\n", cmdName, manBrief)
	} else {
		w = os.Stderr
		rc = 1
		fmt.Fprintf(w, "%s: %v\n", cmdName, err)
	}

	fmt.Fprintf(w, usageFmt, cmdName)
	fmt.Fprintln(w, "\nOptions:")
	set.VisitAll(func(f *flag.Flag) {
		fmt.Fprintf(w, "\t--%s\n\t\t%s\n", f.Name, f.Usage)
	})
	fmt.Fprintf(w, "\nSee the %s man page for more info.\n", manPage)
	os.Exit(rc)
}

func main() {
	set.SetOutput(ioutil.Discard)
	if err := set.Parse(os.Args[1:]); err != nil {
		printUsageAndExit(err)
	}
	if *helpFlag {
		printUsageAndExit(nil)
	}
	if *versionFlag {
		fmt.Println(version)
		return
	}
	if set.NArg() != 2 {
		printUsageAndExit(fmt.Errorf("expected 2 arguments, got %d", set.NArg()))
	}

	command, mountpoint := set.Arg(0), set.Arg(1)
	switch command {
	case "enable":
		fmt.Println("Enabling encryption!!")
	case "disable":
		fmt.Println("Disabling encryption!!")
	default:
		printUsageAndExit(fmt.Errorf("invalid command %q", command))
	}

	if isExt4EncryptionEnabled(mountpoint) {
		fmt.Printf("%q has encryption\n", mountpoint)
	} else {
		fmt.Printf("%q doesn't have encryption\n", mountpoint)
	}
}

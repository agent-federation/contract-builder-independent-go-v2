package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: missing package")
		os.Exit(64)
	}
	// command dispatch
	i := 0
	if args[0] == "verify" || args[0] == "inspect" || args[0] == "explain" {
		i = 1
	}
	var pkg, policy, format, now string
	for i < len(args) {
		switch args[i] {
		case "--trust-policy", "--policy":
			if i+1 >= len(args) {
				usage()
				return
			}
			policy = args[i+1]
			i += 2
		case "--format":
			if i+1 >= len(args) {
				usage()
				return
			}
			format = args[i+1]
			i += 2
		case "--now":
			if i+1 >= len(args) {
				usage()
				return
			}
			now = args[i+1]
			i += 2
		default:
			if strings.HasPrefix(args[i], "--") {
				usage()
				return
			}
			if pkg == "" {
				pkg = args[i]
				i++
			} else {
				usage()
				return
			}
		}
	}
	if pkg == "" {
		usage()
		return
	}
	_ = format
	limits := DefaultLimits()
	report, code, err := RunVerification(pkg, policy, now, limits)
	if err != nil {
		if err == ErrNotFound {
			fmt.Fprintf(os.Stderr, "pap: pap.package.not-found: %v\n", err)
			os.Exit(74)
		}
		if err == ErrNotDir {
			fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: not a directory")
			os.Exit(64)
		}
		if err == ErrUsage {
			fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: invalid usage")
			os.Exit(64)
		}
		if err == ErrPolicyInvalid {
			fmt.Fprintln(os.Stderr, "pap: pap.trust.policy-invalid: invalid policy")
			os.Exit(64)
		}
		fmt.Fprintf(os.Stderr, "pap: pap.internal.error: %v\n", err)
		os.Exit(70)
	}
	// output JSON
	canon, err := canonicalJSON(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pap: pap.internal.error: %v\n", err)
		os.Exit(70)
	}
	if _, err := os.Stdout.Write(append(canon, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "pap: pap.io.error: write failed")
		os.Exit(74)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: usage: pap verify <package> [--trust-policy <path>] [--format json] [--now <rfc3339>]")
	os.Exit(64)
}

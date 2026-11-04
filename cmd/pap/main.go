package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/agent-federation/pap-verifier-go/internal/papverifier"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printSynopsis()
		os.Exit(64)
	}
	// --version / --help
	if args[0] == "--version" {
		impl, ci, _, err := papverifier.ComputeCheckerIdentity()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pap: pap.internal.error: %v\n", err)
			os.Exit(70)
		}
		fmt.Printf("pap %s\n", papverifier.CheckerVersion)
		fmt.Println("papVersion support: 0.1")
		fmt.Println("reportVersion support: 0.1")
		fmt.Printf("implementationDigest: %s\n", impl)
		_ = ci
		os.Exit(0)
	}
	if args[0] == "--help" {
		printSynopsis()
		os.Exit(0)
	}
	cmd := args[0]
	switch cmd {
	case "verify":
		os.Exit(runVerify(args[1:]))
	case "inspect":
		// minimal: not implemented fully; usage
		fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: inspect not implemented in Phase 2a")
		os.Exit(64)
	case "explain":
		fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: explain not implemented in Phase 2a")
		os.Exit(64)
	default:
		fmt.Fprintf(os.Stderr, "pap: pap.cli.usage: unknown command %s\n", cmd)
		os.Exit(64)
	}
}

func printSynopsis() {
	fmt.Println("pap verify PACKAGE [--trust-policy FILE] [--format text|json] [--now RFC3339]")
	fmt.Println("pap inspect PACKAGE [--format text|json]")
	fmt.Println("pap explain PACKAGE --check CHECK_ID [--format text|json]")
	fmt.Println("pap --version")
	fmt.Println("pap --help")
	fmt.Println("Exit codes: PASS 0 FAIL 1 INCOMPLETE/NOT_EVALUATED 2 UNTRUSTED 3 UNSUPPORTED 4 usage 64 internal 70 io 74")
}

func runVerify(args []string) int {
	// parse
	var pkg string
	var policy string
	format := "text"
	var nowStr string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			if i < len(args) {
				if pkg == "" {
					pkg = args[i]
				} else {
					fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: extra positional")
					return 64
				}
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch {
			case a == "--trust-policy":
				if i+1 >= len(args) {
					fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: missing value")
					return 64
				}
				policy = args[i+1]
				i += 2
				continue
			case strings.HasPrefix(a, "--trust-policy="):
				policy = strings.TrimPrefix(a, "--trust-policy=")
				i++
				continue
			case a == "--format":
				if i+1 >= len(args) {
					fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: missing value")
					return 64
				}
				format = args[i+1]
				i += 2
				continue
			case strings.HasPrefix(a, "--format="):
				format = strings.TrimPrefix(a, "--format=")
				i++
				continue
			case a == "--now":
				if i+1 >= len(args) {
					fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: missing value")
					return 64
				}
				nowStr = args[i+1]
				i += 2
				continue
			case strings.HasPrefix(a, "--now="):
				nowStr = strings.TrimPrefix(a, "--now=")
				i++
				continue
			default:
				fmt.Fprintf(os.Stderr, "pap: pap.cli.usage: unknown option %s\n", a)
				return 64
			}
		} else {
			if pkg == "" {
				pkg = a
			} else {
				fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: extra positional")
				return 64
			}
			i++
		}
	}
	if pkg == "" {
		fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: missing PACKAGE")
		return 64
	}
	if format != "text" && format != "json" {
		fmt.Fprintln(os.Stderr, "pap: pap.cli.usage: bad format")
		return 64
	}

	// resolve package root (missing -> 74)
	root, err := papverifier.ResolvePackageRootExported(pkg)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "pap: pap.package.not-found: %v\n", err)
			return 74
		}
		// not directory
		fmt.Fprintf(os.Stderr, "pap: pap.cli.usage: %v\n", err)
		return 64
	}
	_ = root

	// validate policy if provided
	if policy != "" {
		data, err := os.ReadFile(policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pap: pap.trust.policy-invalid: %v\n", err)
			return 64
		}
		_, err = papverifier.ParseStrictJSONExported(data, papverifier.JSONNestingLimit, papverifier.JSONStringLimit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pap: pap.trust.policy-invalid: %v\n", err)
			return 64
		}
	}

	// now
	now := time.Now()
	if nowStr != "" {
		t, err := parseNow(nowStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pap: pap.cli.usage: %v\n", err)
			return 64
		}
		now = t
	}

	// read package
	pr, code, err := papverifier.ReadPackageExported(pkg)
	if err != nil {
		// internal?
		fmt.Fprintf(os.Stderr, "pap: pap.internal.error: %v\n", err)
		return 70
	}
	if code == 74 {
		fmt.Fprintf(os.Stderr, "pap: pap.package.not-found: %v\n", err)
		return 74
	}
	if code == 64 {
		fmt.Fprintf(os.Stderr, "pap: pap.cli.usage: %v\n", err)
		return 64
	}

	// checker identity
	implDigest, checkerIdentity, _, err := papverifier.ComputeCheckerIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pap: pap.internal.error: %v\n", err)
		return 70
	}

	report := papverifier.BuildReport(pr, policy, now, implDigest, checkerIdentity, nil)

	// output
	if format == "json" {
		b, err := marshalJCS(report)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pap: pap.io.error: %v\n", err)
			return 74
		}
		os.Stdout.Write(b)
		os.Stdout.Write([]byte("\n"))
	} else {
		// minimal text
		fmt.Printf("VERDICT: %s\n", report["verdict"])
	}

	// exit code
	verdict := report["verdict"].(string)
	switch verdict {
	case "PASS":
		return 0
	case "FAIL":
		return 1
	case "INCOMPLETE", "NOT_EVALUATED":
		return 2
	case "UNTRUSTED":
		return 3
	case "UNSUPPORTED":
		return 4
	}
	return 2
}

func parseNow(s string) (time.Time, error) {
	// try RFC3339 and Nano
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("bad --now")
}

func marshalJCS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// remove trailing newline from Encode
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	return b, nil
}

// Need bytes import

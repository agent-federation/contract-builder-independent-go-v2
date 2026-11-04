package main

import (
	"sort"
	"strings"
)

type Diagnostic struct {
	Code     string
	Severity string
	Scope    string
	Message  string
}

func diagMap(d Diagnostic) map[string]any {
	return map[string]any{
		"code":     d.Code,
		"severity": d.Severity,
		"scope":    d.Scope,
		"message":  d.Message,
	}
}

func sevRank(s string) int {
	switch s {
	case "error":
		return 0
	case "warning":
		return 1
	default:
		return 2
	}
}

func sortDiagnostics(ds []Diagnostic) {
	sort.Slice(ds, func(i, j int) bool {
		if sevRank(ds[i].Severity) != sevRank(ds[j].Severity) {
			return sevRank(ds[i].Severity) < sevRank(ds[j].Severity)
		}
		if ds[i].Code != ds[j].Code {
			return ds[i].Code < ds[j].Code
		}
		return ds[i].Scope < ds[j].Scope
	})
}

func sortLimitations(ls []map[string]any) {
	sort.Slice(ls, func(i, j int) bool {
		if ls[i]["code"].(string) != ls[j]["code"].(string) {
			return ls[i]["code"].(string) < ls[j]["code"].(string)
		}
		return ls[i]["detail"].(string) < ls[j]["detail"].(string)
	})
}

func verdictExit(v string) int {
	switch v {
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

func isDecidedStatus(s string) bool {
	switch s {
	case "PASS", "FAIL", "VALID", "INVALID", "TRUSTED", "UNTRUSTED", "ACCEPTED", "REJECTED", "STALE", "NOT_APPLICABLE":
		return true
	}
	return false
}

// valid path grammar
func validPathGrammar(p string, limits Limits) bool {
	if p == "" {
		return false
	}
	if len(p) > limits.PathBytes {
		return false
	}
	if p[0] == '/' || p[len(p)-1] == '/' {
		return false
	}
	segments := strings.Split(p, "/")
	if len(segments) > limits.PathSegments || len(segments) < 1 {
		return false
	}
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		if len(seg) > limits.SegmentBytes {
			return false
		}
		for _, c := range seg {
			if !( (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

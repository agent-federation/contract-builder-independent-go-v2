package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

func H(domain string, octets []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0x00})
	h.Write(octets)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func sha256RawBytes(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func frameRecord(tag string, parts [][]byte) []byte {
	var out []byte
	out = appendU32(out, uint32(len(tag)))
	out = append(out, []byte(tag)...)
	out = appendU32(out, uint32(len(parts)))
	for _, p := range parts {
		out = appendU32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func normalizeInputBytes(raw []byte, normalization string) []byte {
	if normalization == "none" {
		return append([]byte(nil), raw...)
	}
	// NUL check
	for _, c := range raw {
		if c == 0 {
			return append([]byte(nil), raw...)
		}
	}
	if !utf8.Valid(raw) {
		return append([]byte(nil), raw...)
	}
	s := string(raw)
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	norm = strings.ReplaceAll(norm, "\r", "\n")
	return []byte(norm)
}

func normalizeLFText(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("binary file in closure")
	}
	s := string(raw)
	for _, c := range raw {
		if c == 0 {
			return nil, fmt.Errorf("binary file in closure")
		}
	}
	norm := strings.ReplaceAll(s, "\r\n", "\n")
	norm = strings.ReplaceAll(norm, "\r", "\n")
	return []byte(norm), nil
}

type ClosureFile struct {
	Path    string
	Content []byte
}

type Dependency struct {
	Name       string
	Version    string
	Integrity  string
}

func ExtensionClosureDigest(kind, id, version string, files []ClosureFile, deps []Dependency) string {
	// sort files by path
	fs := append([]ClosureFile(nil), files...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
	ds := append([]Dependency(nil), deps...)
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].Name != ds[j].Name {
			return ds[i].Name < ds[j].Name
		}
		return ds[i].Version < ds[j].Version
	})
	var records [][]byte
	// extension record
	records = append(records, frameRecord("extension", [][]byte{
		[]byte(kind), []byte(id), []byte(version),
	}))
	for _, f := range fs {
		norm, err := normalizeLFText(f.Content)
		if err != nil {
			// binary error; but function returns digest; panic? We'll return empty? Better error not in signature.
			// For safety, treat as error by returning ""
			return ""
		}
		records = append(records, frameRecord("file", [][]byte{
			[]byte(f.Path), norm,
		}))
	}
	for _, d := range ds {
		records = append(records, frameRecord("dependency", [][]byte{
			[]byte(d.Name), []byte(d.Version), []byte(d.Integrity),
		}))
	}
	// concatenate all records
	var payload []byte
	for _, r := range records {
		payload = append(payload, r...)
	}
	return H("pap.extension.closure.v1", payload)
}

func CheckerIdentity(id, version string, files []ClosureFile, deps []Dependency) (string, string) {
	impl := ExtensionClosureDigest("checker", id, version, files, deps)
	canon, _ := canonicalJSON(map[string]any{
		"id":                 id,
		"version":            version,
		"implementationDigest": impl,
	})
	ci := H("pap.checker.identity.v1", canon)
	return impl, ci
}

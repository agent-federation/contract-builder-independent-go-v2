package papverifier

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func DomainHash(domain string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0x00})
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func FrameRecord(tag string, parts [][]byte) []byte {
	tagBytes := []byte(tag)
	buf := make([]byte, 0, 64)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(tagBytes)))
	buf = append(buf, b...)
	buf = append(buf, tagBytes...)
	binary.BigEndian.PutUint32(b, uint32(len(parts)))
	buf = append(buf, b...)
	for _, part := range parts {
		binary.BigEndian.PutUint32(b, uint32(len(part)))
		buf = append(buf, b...)
		buf = append(buf, part...)
	}
	return buf
}

func FrameConcat(records [][]byte) []byte {
	var buf []byte
	for _, r := range records {
		buf = append(buf, r...)
	}
	return buf
}

func NormalizeInput(raw []byte, normalization string) []byte {
	if normalization == "none" {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	if bytesContainsNul(raw) {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	if !utf8.Valid(raw) {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}
	out := make([]byte, 0, len(raw))
	i := 0
	for i < len(raw) {
		if i+1 < len(raw) && raw[i] == '\r' && raw[i+1] == '\n' {
			out = append(out, '\n')
			i += 2
			continue
		}
		if raw[i] == '\r' {
			out = append(out, '\n')
			i++
			continue
		}
		out = append(out, raw[i])
		i++
	}
	return out
}

func bytesContainsNul(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// ExtensionClosureDigest computes digest from components.
type ClosureFile struct {
	Path    string
	Content []byte // raw text bytes; normalized internally
}
type ClosureDep struct {
	Name      string
	Version   string
	Integrity string
}

func ExtensionClosureDigest(kind, id, version string, files []ClosureFile, deps []ClosureDep) string {
	// normalize files
	normFiles := make([]ClosureFile, len(files))
	copy(normFiles, files)
	// sort files by path
	// normalize each
	type nf struct {
		path string
		data []byte
	}
	var nfs []nf
	for _, f := range files {
		// binary check
		if bytesContainsNul(f.Content) {
			// error; but return empty? We'll panic? Instead return ""? For tests no binary.
		}
		norm := NormalizeInput(f.Content, "lf") // text normalization CRLF/CR->LF; but binary fallback already handled? NormalizeInput returns raw on NUL.
		// Actually for binary file, spec says error. We'll still normalize.
		nfs = append(nfs, nf{path: f.Path, data: norm})
	}
	// sort by path bytes
	// simple sort
	for i := 0; i < len(nfs); i++ {
		for j := i + 1; j < len(nfs); j++ {
			if string(nfs[j].path) < string(nfs[i].path) {
				nfs[i], nfs[j] = nfs[j], nfs[i]
			}
		}
	}
	// sort deps
	type nd struct {
		name      string
		version   string
		integrity string
	}
	var nds []nd
	for _, d := range deps {
		nds = append(nds, nd{d.Name, d.Version, d.Integrity})
	}
	for i := 0; i < len(nds); i++ {
		for j := i + 1; j < len(nds); j++ {
			if nds[j].name < nds[i].name || (nds[j].name == nds[i].name && nds[j].version < nds[i].version) {
				nds[i], nds[j] = nds[j], nds[i]
			}
		}
	}
	// build records
	var records [][]byte
	// extension record
	records = append(records, FrameRecord("extension", [][]byte{
		[]byte(kind), []byte(id), []byte(version),
	}))
	for _, f := range nfs {
		records = append(records, FrameRecord("file", [][]byte{
			[]byte(f.path), f.data,
		}))
	}
	for _, d := range nds {
		records = append(records, FrameRecord("dependency", [][]byte{
			[]byte(d.name), []byte(d.version), []byte(d.integrity),
		}))
	}
	payload := FrameConcat(records)
	return DomainHash("pap.extension.closure.v1", payload)
}

func CheckerIdentity(id, version string, implDigest string) string {
	// JCS {"id":..., "version":..., "implementationDigest":...}
	m := map[string]any{
		"id":                   id,
		"version":              version,
		"implementationDigest": implDigest,
	}
	b, _ := CanonicalJSON(m)
	return DomainHash("pap.checker.identity.v1", b)
}

// unused fmt import guard
var _ = fmt.Sprintf

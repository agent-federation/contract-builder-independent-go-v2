package papverifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxInt53 = int64(1) << 53
	minInt53 = -(int64(1) << 53)
)

// CanonicalJSON returns RFC 8785 JCS bytes for the given parsed value (I-JSON subset).
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		if err := validateString(val); err != nil {
			return err
		}
		buf.WriteString(escapeString(val))
	case int64:
		if val < -(1<<53)+1 || val > (1<<53)-1 {
			return fmt.Errorf("integer out of range")
		}
		fmt.Fprintf(buf, "%d", val)
	case float64:
		return fmt.Errorf("float not allowed")
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			if err := validateString(k); err != nil {
				return err
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(escapeString(k))
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		// try map[string]any via json? no
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func validateString(s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("invalid UTF-8 string")
	}
	for _, r := range s {
		if r >= 0xD800 && r <= 0xDFFF {
			return fmt.Errorf("lone surrogate")
		}
	}
	return nil
}

func escapeString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return buf.String()
}

func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	// compare slices
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// helper to canonicalize raw JSON bytes via strict parse
func CanonicalJSONBytes(data []byte, maxDepth, maxStringBytes int) ([]byte, error) {
	v, err := parseStrictJSON(data, maxDepth, maxStringBytes)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(v)
}

// avoid unused import
var _ = json.Marshal

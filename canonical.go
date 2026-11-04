package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
	"unicode/utf16"
)

func canonicalJSON(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeCanonical(b *strings.Builder, v any) error {
	switch val := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if val {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		b.WriteString(strconv.FormatInt(val, 10))
	case int:
		b.WriteString(strconv.Itoa(val))
	case string:
		s, err := escapeJSONString(val)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []string:
		b.WriteByte('[')
		for i, e := range val {
			if i > 0 { b.WriteByte(',') }
			b.WriteString(strconv.Quote(e))
		}
		b.WriteByte(']')
	case []map[string]any:
		b.WriteByte('[')
		for i, e := range val {
			if i > 0 { b.WriteByte(',') }
			if err := writeCanonical(b, deepCopyMap(e)); err != nil { return err }
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range val {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			ks, err := escapeJSONString(k)
			if err != nil {
				return err
			}
			b.WriteString(ks)
			b.WriteByte(':')
			if err := writeCanonical(b, val[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
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

func escapeJSONString(s string) (string, error) {
	// validate scalar values
	for _, r := range s {
		if !utf8.ValidRune(r) {
			return "", fmt.Errorf("invalid scalar in string")
		}
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf("\\u%04x", r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}


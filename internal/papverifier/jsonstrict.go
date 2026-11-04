package papverifier

import (
	"fmt"
	"unicode/utf8"
)

// parseStrictJSON parses JSON with duplicate-key rejection, integer-only numbers,
// UTF-8 validation, nesting and string-size limits. Returns parsed value as
// map[string]any, []any, string, bool, nil, or int64.
func parseStrictJSON(data []byte, maxDepth, maxStringBytes int) (any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	// BOM rejection
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return nil, fmt.Errorf("BOM not allowed")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	p := &jsonParser{data: data, maxDepth: maxDepth, maxStringBytes: maxStringBytes}
	val, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	// trailing data
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, fmt.Errorf("trailing data")
	}
	return val, nil
}

type jsonParser struct {
	data           []byte
	pos            int
	maxDepth       int
	maxStringBytes int
}

func (p *jsonParser) skipWS() {
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			p.pos++
		} else {
			break
		}
	}
}

func (p *jsonParser) parseValue(depth int) (any, error) {
	if depth > p.maxDepth {
		return nil, fmt.Errorf("nesting depth exceeded")
	}
	p.skipWS()
	if p.pos >= len(p.data) {
		return nil, fmt.Errorf("unexpected EOF")
	}
	switch p.data[p.pos] {
	case '{':
		return p.parseObject(depth + 1)
	case '[':
		return p.parseArray(depth + 1)
	case '"':
		return p.parseString()
	case 't', 'f':
		return p.parseBool()
	case 'n':
		return p.parseNull()
	default:
		return p.parseNumber()
	}
}

func (p *jsonParser) parseObject(depth int) (map[string]any, error) {
	if p.data[p.pos] != '{' {
		return nil, fmt.Errorf("expected object")
	}
	p.pos++
	obj := map[string]any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, fmt.Errorf("expected string key")
		}
		key, err := p.parseStringRaw()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key: %s", key)
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, fmt.Errorf("expected colon")
		}
		p.pos++
		val, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		obj[key] = val
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, fmt.Errorf("unexpected EOF in object")
		}
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.data[p.pos] == '}' {
			p.pos++
			break
		}
		return nil, fmt.Errorf("expected , or }")
	}
	return obj, nil
}

func (p *jsonParser) parseArray(depth int) ([]any, error) {
	if p.data[p.pos] != '[' {
		return nil, fmt.Errorf("expected array")
	}
	p.pos++
	arr := []any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		val, err := p.parseValue(depth)
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, fmt.Errorf("unexpected EOF in array")
		}
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.data[p.pos] == ']' {
			p.pos++
			break
		}
		return nil, fmt.Errorf("expected , or ]")
	}
	return arr, nil
}

func (p *jsonParser) parseString() (string, error) {
	return p.parseStringRaw()
}

func (p *jsonParser) parseStringRaw() (string, error) {
	if p.data[p.pos] != '"' {
		return "", fmt.Errorf("expected string")
	}
	p.pos++
	var b []byte
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == '"' {
			p.pos++
			s := string(b)
			if len(s) > p.maxStringBytes {
				return "", fmt.Errorf("string too long")
			}
			return s, nil
		}
		if c < 0x20 {
			return "", fmt.Errorf("unescaped control char")
		}
		if c == '\\' {
			p.pos++
			if p.pos >= len(p.data) {
				return "", fmt.Errorf("bad escape")
			}
			esc := p.data[p.pos]
			switch esc {
			case '"', '\\', '/':
				b = append(b, esc)
				p.pos++
			case 'b':
				b = append(b, '\b')
				p.pos++
			case 'f':
				b = append(b, '\f')
				p.pos++
			case 'n':
				b = append(b, '\n')
				p.pos++
			case 'r':
				b = append(b, '\r')
				p.pos++
			case 't':
				b = append(b, '\t')
				p.pos++
			case 'u':
				p.pos++
				if p.pos+4 > len(p.data) {
					return "", fmt.Errorf("bad unicode escape")
				}
				cp, err := parseHex4(p.data[p.pos : p.pos+4])
				if err != nil {
					return "", err
				}
				p.pos += 4
				// surrogate handling
				if cp >= 0xD800 && cp <= 0xDBFF {
					// expect low surrogate
					if p.pos+6 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", fmt.Errorf("lone surrogate")
					}
					p.pos += 2
					cp2, err := parseHex4(p.data[p.pos : p.pos+4])
					if err != nil {
						return "", err
					}
					p.pos += 4
					if cp2 < 0xDC00 || cp2 > 0xDFFF {
						return "", fmt.Errorf("invalid surrogate pair")
					}
					r := 0x10000 + (cp-0xD800)*0x400 + (cp2 - 0xDC00)
					// encode
					var tmp [4]byte
					n := utf8.EncodeRune(tmp[:], rune(r))
					b = append(b, tmp[:n]...)
				} else if cp >= 0xDC00 && cp <= 0xDFFF {
					return "", fmt.Errorf("lone surrogate")
				} else {
					var tmp [4]byte
					n := utf8.EncodeRune(tmp[:], rune(cp))
					b = append(b, tmp[:n]...)
				}
			default:
				return "", fmt.Errorf("unknown escape")
			}
		} else {
			b = append(b, c)
			p.pos++
		}
	}
	return "", fmt.Errorf("unterminated string")
}

func parseHex4(b []byte) (int, error) {
	v := 0
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= int(c - '0')
		case c >= 'a' && c <= 'f':
			v |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= int(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad hex")
		}
	}
	return v, nil
}

func (p *jsonParser) parseBool() (bool, error) {
	if p.pos+4 <= len(p.data) && string(p.data[p.pos:p.pos+4]) == "true" {
		p.pos += 4
		return true, nil
	}
	if p.pos+5 <= len(p.data) && string(p.data[p.pos:p.pos+5]) == "false" {
		p.pos += 5
		return false, nil
	}
	return false, fmt.Errorf("invalid literal")
}

func (p *jsonParser) parseNull() (any, error) {
	if p.pos+4 <= len(p.data) && string(p.data[p.pos:p.pos+4]) == "null" {
		p.pos += 4
		return nil, nil
	}
	return nil, fmt.Errorf("invalid literal")
}

func (p *jsonParser) parseNumber() (any, error) {
	start := p.pos
	// collect
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			p.pos++
		} else {
			break
		}
	}
	tok := string(p.data[start:p.pos])
	if tok == "" {
		return nil, fmt.Errorf("expected number")
	}
	// integer-only: must match -?(0|[1-9][0-9]*)
	// validate no decimal/exponent
	neg := false
	i := 0
	if i < len(tok) && tok[i] == '-' {
		neg = true
		i++
	} else if i < len(tok) && tok[i] == '+' {
		return nil, fmt.Errorf("plus sign not allowed")
	}
	if i >= len(tok) {
		return nil, fmt.Errorf("bad number")
	}
	if tok[i] == '0' {
		if i+1 != len(tok) {
			return nil, fmt.Errorf("leading zero or non-integer")
		}
	} else {
		for ; i < len(tok); i++ {
			if tok[i] < '0' || tok[i] > '9' {
				return nil, fmt.Errorf("non-integer number")
			}
		}
	}
	// parse int64
	var val int64
	// use manual
	neg2 := neg
	digits := tok
	if neg2 {
		digits = tok[1:]
	}
	for _, c := range digits {
		val = val*10 + int64(c-'0')
	}
	if neg2 {
		val = -val
	}
	// range check for I-JSON handled by JCS; store as int64.
	_ = neg
	return val, nil
}

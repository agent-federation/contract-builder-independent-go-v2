package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// parseStrictJSON parses JSON with strict I-JSON rules. Returns Go values:
// nil, bool, int64, string, []any, map[string]any.
func parseStrictJSON(data []byte, limits Limits) (any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	if data[0] == 0xEF && len(data) >= 3 && data[1] == 0xBB && data[2] == 0xBF {
		return nil, fmt.Errorf("BOM not allowed")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid UTF-8")
	}
	p := &jsonParser{data: data, limits: limits}
	val, err := p.parseValue(0)
	if err != nil {
		return nil, err
	}
	// trailing whitespace ok, trailing data not
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, fmt.Errorf("trailing data")
	}
	return val, nil
}

type jsonParser struct {
	data   []byte
	pos    int
	limits Limits
	depth  int
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
	if depth > p.limits.JSONNesting {
		return nil, fmt.Errorf("nesting limit exceeded")
	}
	p.skipWS()
	if p.pos >= len(p.data) {
		return nil, fmt.Errorf("unexpected EOF")
	}
	c := p.data[p.pos]
	switch {
	case c == '{':
		return p.parseObject(depth + 1)
	case c == '[':
		return p.parseArray(depth + 1)
	case c == '"':
		return p.parseString()
	case c == 't' || c == 'f':
		return p.parseBool()
	case c == 'n':
		return p.parseNull()
	default:
		return p.parseNumber()
	}
}

func (p *jsonParser) parseObject(depth int) (any, error) {
	if depth > p.limits.JSONNesting {
		return nil, fmt.Errorf("nesting limit exceeded")
	}
	p.pos++ // {
	p.skipWS()
	obj := map[string]any{}
	seen := map[string]bool{}
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
		if seen[key] {
			return nil, fmt.Errorf("duplicate key: %s", key)
		}
		seen[key] = true
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

func (p *jsonParser) parseArray(depth int) (any, error) {
	if depth > p.limits.JSONNesting {
		return nil, fmt.Errorf("nesting limit exceeded")
	}
	p.pos++ // [
	p.skipWS()
	arr := []any{}
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

func (p *jsonParser) parseString() (any, error) {
	s, err := p.parseStringRaw()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (p *jsonParser) parseStringRaw() (string, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != '"' {
		return "", fmt.Errorf("expected string")
	}
	p.pos++ // opening quote
	var b strings.Builder
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == '"' {
			p.pos++
			s := b.String()
			if len(s) > p.limits.JSONStringBytes {
				return "", fmt.Errorf("string too long")
			}
			return s, nil
		}
		if c < 0x20 {
			return "", fmt.Errorf("unescaped control char")
		}
		if c != '\\' {
			// multibyte or single
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", fmt.Errorf("invalid UTF-8")
			}
			if !utf8.ValidRune(r) {
				return "", fmt.Errorf("invalid scalar")
			}
			b.WriteRune(r)
			p.pos += size
			continue
		}
		// escape
		p.pos++
		if p.pos >= len(p.data) {
			return "", fmt.Errorf("bad escape")
		}
		esc := p.data[p.pos]
		switch esc {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			if p.pos+4 >= len(p.data) { // need 4 hex after u
				// actually need pos+4 < len? we need 4 chars after u => indices pos+1..pos+4
			}
			if p.pos+4 >= len(p.data) {
				return "", fmt.Errorf("bad unicode escape")
			}
			hex := string(p.data[p.pos+1 : p.pos+5])
			cp, err := strconv.ParseUint(hex, 16, 32)
			if err != nil {
				return "", fmt.Errorf("bad unicode escape")
			}
			r := rune(cp)
			if r >= 0xD800 && r <= 0xDBFF {
				// need low surrogate
				if p.pos+10 >= len(p.data) {
					return "", fmt.Errorf("lone surrogate")
				}
				if p.data[p.pos+5] != '\\' || p.data[p.pos+6] != 'u' {
					return "", fmt.Errorf("lone surrogate")
				}
				hex2 := string(p.data[p.pos+7 : p.pos+11])
				cp2, err := strconv.ParseUint(hex2, 16, 32)
				if err != nil {
					return "", fmt.Errorf("bad surrogate")
				}
				r2 := rune(cp2)
				if r2 < 0xDC00 || r2 > 0xDFFF {
					return "", fmt.Errorf("invalid surrogate pair")
				}
				runeVal := 0x10000 + (r-0xD800)*0x400 + (r2 - 0xDC00)
				b.WriteRune(rune(runeVal))
				p.pos += 10 // move to last hex of second escape; outer ++ moves past
			} else if r >= 0xDC00 && r <= 0xDFFF {
				return "", fmt.Errorf("lone surrogate")
			} else {
				b.WriteRune(r)
				p.pos += 4
			}
		default:
			return "", fmt.Errorf("invalid escape")
		}
		p.pos++
	}
	return "", fmt.Errorf("unterminated string")
}

func (p *jsonParser) parseBool() (any, error) {
	if strings.HasPrefix(string(p.data[p.pos:]), "true") {
		p.pos += 4
		return true, nil
	}
	if strings.HasPrefix(string(p.data[p.pos:]), "false") {
		p.pos += 5
		return false, nil
	}
	return nil, fmt.Errorf("invalid literal")
}

func (p *jsonParser) parseNull() (any, error) {
	if strings.HasPrefix(string(p.data[p.pos:]), "null") {
		p.pos += 4
		return nil, nil
	}
	return nil, fmt.Errorf("invalid literal")
}

func (p *jsonParser) parseNumber() (any, error) {
	start := p.pos
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
	// validate integer-only format
	if !isValidIntegerToken(tok) {
		return nil, fmt.Errorf("invalid number token")
	}
	val, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid number")
	}
	// range check 2^53
	if val > 9007199254740991 || val < -9007199254740991 {
		return nil, fmt.Errorf("number out of range")
	}
	return val, nil
}

func isValidIntegerToken(tok string) bool {
	// -?(0|[1-9][0-9]*)
	s := tok
	if strings.HasPrefix(s, "-") {
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		return false
	}
	if s == "" {
		return false
	}
	if s == "0" {
		return true
	}
	if s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	// reject -0
	if tok == "-0" {
		return false
	}
	return true
}

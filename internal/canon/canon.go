// Package canon implements a JSON canonicalizer sufficient for ReinsAARM
// receipts. Object keys are sorted by Unicode code point. Receipt keys are
// ASCII, so this matches RFC 8785 (JCS) for the documents we sign. Non-ASCII
// string values are emitted as raw UTF-8, not \u escapes.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// JSON returns the canonical encoding of a JSON document.
func JSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF && err != nil {
		return nil, fmt.Errorf("canonical json: trailing data: %w", err)
	} else if err == nil {
		return nil, fmt.Errorf("canonical json: trailing data")
	}
	var b strings.Builder
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Value canonicalizes a Go value by a JSON round trip.
func Value(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return JSON(raw)
}

func writeValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		if err := writeNumber(b, string(t)); err != nil {
			return err
		}
	case string:
		writeString(b, t)
	case []any:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, el); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeValue(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported %T", v)
	}
	return nil
}

func writeNumber(b *strings.Builder, s string) error {
	if _, err := strconv.ParseFloat(s, 64); err != nil {
		return fmt.Errorf("canonical json: bad number %q", s)
	}
	b.WriteString(s)
	return nil
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
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
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

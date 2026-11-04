package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestJCSUTF16(t *testing.T) {
	v := map[string]any{"a": int64(1), "😀": int64(2), "\ufffd": int64(3), "A": int64(4), "b": int64(5)}
	canon, err := canonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"A":4,"a":1,"b":5,"😀":2,"�":3}`
	if string(canon) != expected {
		t.Fatalf("got %s", string(canon))
	}
	h := sha256.Sum256(canon)
	if hex.EncodeToString(h[:]) != "9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508" {
		t.Fatalf("hash mismatch")
	}
}

func TestJCSStringEscape(t *testing.T) {
	v := map[string]any{"s": "\u0001\t\n\"\\\u00e9😀"}
	canon, err := canonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"s":"\u0001\t\n\"\\é😀"}`
	if string(canon) != expected {
		t.Fatalf("got %s", string(canon))
	}
	h := sha256.Sum256(canon)
	if hex.EncodeToString(h[:]) != "9033f8f21bc1c3367ebcad55e2298bf113b63f9e5f21c20678de00e760c5ff5d" {
		t.Fatalf("hash mismatch")
	}
}

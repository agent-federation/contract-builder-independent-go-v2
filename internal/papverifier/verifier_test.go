package papverifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJCSKeyOrder(t *testing.T) {
	v := map[string]any{"a": int64(1), "😀": int64(2), "\ufffd": int64(3), "A": int64(4), "b": int64(5)}
	b, err := CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"A":4,"a":1,"b":5,"😀":2,"�":3}` {
		t.Fatalf("got %s", string(b))
	}
	if SHA256Hex(b) != "9267454f732ed7ef9939b28dc1e451c88c2967ff4a6b1746bf638d313e72b508" {
		t.Fatal("hash mismatch")
	}
}

func TestStrictJSONDuplicateKey(t *testing.T) {
	_, err := parseStrictJSON([]byte(`{"a":1,"a":2}`), 64, 1024)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestE3CheckerIdentity(t *testing.T) {
	files := []ClosureFile{
		{Path: "src/checks/digest.ts", Content: []byte("export const checkId = \"pap.check.digest-integrity/1\";\n")},
		{Path: "src/checks/source.ts", Content: []byte("export const spanCheck = true;\n")},
	}
	deps := []ClosureDep{
		{Name: "zod", Version: "3.23.8", Integrity: "sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0="},
	}
	impl := ExtensionClosureDigest("checker", "pap.verifier.reference", "0.1.0", files, deps)
	ci := CheckerIdentity("pap.verifier.reference", "0.1.0", impl)
	if impl != "sha256:73f738b733b177c04597b0e6ab9c4d267059ea1556e6f943d543c252c5ef15c0" {
		t.Fatalf("impl %s", impl)
	}
	if ci != "sha256:15a0b0149dc95f7b9711e7b28fc4189ed8539b03ffd2c96e967205316d75963f" {
		t.Fatalf("ci %s", ci)
	}
}

func TestFramingVectors(t *testing.T) {
	hello := []byte("hello")
	if DomainHash("pap.artifact.v1", hello) != "sha256:49ade3eaed5c81a07ee5245b923abe3c629747f0eebe57a0052307d5965d5112" {
		t.Fatal("artifact hash")
	}
	r1 := FrameRecord("x", [][]byte{[]byte("ab"), []byte("c")})
	r2 := FrameRecord("x", [][]byte{[]byte("a"), []byte("bc")})
	h1 := DomainHash("pap.test.v1", r1)
	h2 := DomainHash("pap.test.v1", r2)
	if h1 == h2 {
		t.Fatal("framing collision")
	}
	if h1 != "sha256:a4ff1eac1c490e25d4a23ef485f9219a4a51b2c370ba86ed20ba0d8e5c7334e5" {
		t.Fatal("h1")
	}
}

func TestPackageIdentityVector(t *testing.T) {
	// read fixture manifest
	p := filepath.Join("..", "..", "..", "pap", "fixtures", "pap-v0.1", "F01-unchanged", "assurance-package.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skip("fixture not found")
	}
	canon, err := CanonicalJSONBytes(data, 64, 16*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	id := DomainHash("pap.package.v1", canon)
	if id != "sha256:77a8d1d0882428efdfa5bfc38faa1ff7ba772aff9373b9e6135a8bb744119020" {
		t.Fatalf("got %s", id)
	}
}

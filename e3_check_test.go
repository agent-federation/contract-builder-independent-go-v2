package main

import "testing"

func TestE3CheckerIdentity(t *testing.T) {
	files := []ClosureFile{
		{Path: "src/checks/digest.ts", Content: []byte("export const checkId = \"pap.check.digest-integrity/1\";\n")},
		{Path: "src/checks/source.ts", Content: []byte("export const spanCheck = true;\n")},
	}
	deps := []Dependency{{Name: "zod", Version: "3.23.8", Integrity: "sha512-9K5fXZ0G8p3oUo4WQ9m2l1v0B9m3r7Yqk1s2V4pL6c0="}}
	impl, ci := CheckerIdentity("pap.verifier.reference", "0.1.0", files, deps)
	if impl != "sha256:73f738b733b177c04597b0e6ab9c4d267059ea1556e6f943d543c252c5ef15c0" {
		t.Fatalf("impl mismatch: %s", impl)
	}
	if ci != "sha256:15a0b0149dc95f7b9711e7b28fc4189ed8539b03ffd2c96e967205316d75963f" {
		t.Fatalf("ci mismatch: %s", ci)
	}
}

package papverifier

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const CheckerID = "pap.verifier.go"
const CheckerVersion = "0.1.0"

// SourceRoot locates the implementation checkout root containing go.mod.
func SourceRoot() (string, error) {
	if env := os.Getenv("PAP_SOURCE_ROOT"); env != "" {
		if _, err := os.Stat(filepath.Join(env, "go.mod")); err == nil {
			return env, nil
		}
	}
	// try cwd
	cwd, _ := os.Getwd()
	for dir := cwd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
	}
	// try executable dir
	exe, _ := os.Executable()
	if exe != "" {
		dir := filepath.Dir(exe)
		for ; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir, nil
			}
		}
	}
	return "", fmt.Errorf("source root not found")
}

// ClosureFiles returns sorted repo-relative paths included in checker closure.
func ClosureFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			// skip tests, fixtures, docs, snapshot, hidden dirs, vendor
			if base == "testdata" || base == "docs" || base == "pap" || base == "snapshot" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			if base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		base := filepath.Base(rel)
		// include go.mod/go.sum at root
		if rel == "go.mod" || rel == "go.sum" {
			files = append(files, rel)
			return nil
		}
		// include .go non-test under cmd/internal
		if strings.HasSuffix(base, ".go") && !strings.HasSuffix(base, "_test.go") {
			if strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "internal/") {
				files = append(files, rel)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// ComputeCheckerIdentity returns implementationDigest, checkerIdentity, and file list.
func ComputeCheckerIdentity() (string, string, []string, error) {
	root, err := SourceRoot()
	if err != nil {
		return "", "", nil, err
	}
	files, err := ClosureFiles(root)
	if err != nil {
		return "", "", nil, err
	}
	var closureFiles []ClosureFile
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return "", "", nil, err
		}
		// binary check
		if bytesContainsNul(data) {
			return "", "", nil, fmt.Errorf("binary file in closure: %s", rel)
		}
		closureFiles = append(closureFiles, ClosureFile{Path: rel, Content: data})
	}
	implDigest := ExtensionClosureDigest("checker", CheckerID, CheckerVersion, closureFiles, nil)
	ci := CheckerIdentity(CheckerID, CheckerVersion, implDigest)
	return implDigest, ci, files, nil
}

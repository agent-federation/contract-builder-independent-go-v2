package main

import (
	"embed"
	"io/fs"
	"path/filepath"
)

//go:embed *.go go.mod
var embeddedFiles embed.FS

func gatherEmbeddedClosure() ([]ClosureFile, []Dependency) {
	var files []ClosureFile
	err := fs.WalkDir(embeddedFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if !includeClosureFile(rel) {
			return nil
		}
		b, err := embeddedFiles.ReadFile(path)
		if err != nil {
			return nil
		}
		files = append(files, ClosureFile{Path: rel, Content: b})
		return nil
	})
	_ = err
	return files, nil
}

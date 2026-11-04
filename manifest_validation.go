package main

import (
	"time"
	"regexp"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// validateManifest returns diagnostics and whether schema/crossfield valid.
func validateManifest(val any, limits Limits) ([]Diagnostic, bool) {
	var diags []Diagnostic
	ok := true
	fail := func(code, scope, msg string) {
		diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: scope, Message: msg})
		ok = false
	}
	warn := func(code, scope, msg string) {
		diags = append(diags, Diagnostic{Code: code, Severity: "warning", Scope: scope, Message: msg})
	}
	info := func(code, scope, msg string) {
		diags = append(diags, Diagnostic{Code: code, Severity: "info", Scope: scope, Message: msg})
	}

	m, isMap := val.(map[string]any)
	if !isMap {
		fail("pap.package.schema", "manifest", "manifest must be object")
		return diags, false
	}

	// top-level allowed keys
	allowedTop := map[string]bool{
		"papVersion": true, "package": true, "subject": true, "build": true,
		"artifacts": true, "inputs": true, "sources": true, "claims": true,
		"profile": true, "checkSpecs": true, "extensions": true, "requiredFeatures": true,
	}
	for k := range m {
		if !allowedTop[k] {
			fail("pap.package.unknown-field", "manifest", "unknown field: "+k)
		}
	}
	// required
	for _, r := range []string{"papVersion", "package", "artifacts", "checkSpecs"} {
		if _, ok2 := m[r]; !ok2 {
			fail("pap.package.schema", "manifest", "missing required field: "+r)
		}
	}

	// papVersion
	pv, _ := m["papVersion"].(string)
	pvPresent := false
	if v, exists := m["papVersion"]; exists {
		s, ok2 := v.(string)
		if !ok2 {
			fail("pap.package.schema", "manifest", "papVersion must be string")
		} else {
			pvPresent = true
			pv = s
			if !matchPattern(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`, pv) {
				fail("pap.package.schema", "manifest", "invalid papVersion format")
			} else {
				parts := strings.Split(pv, ".")
				major, _ := strconv.Atoi(parts[0])
				minor, _ := strconv.Atoi(parts[1])
				if pv != "0.1" {
					if major == 0 && minor > 1 {
						warn("pap.compat.minor-newer", "manifest", "newer minor version")
					} else {
						warn("pap.compat.version-unsupported", "manifest", "unsupported version")
					}
				}
			}
		}
	}
	_ = pvPresent

	// package
	pkg, ok2 := m["package"].(map[string]any)
	if _, exists := m["package"]; exists {
		if !ok2 {
			fail("pap.package.schema", "manifest", "package must be object")
		} else {
			// allowed
			allowedPkg := map[string]bool{"id": true, "title": true, "createdAt": true, "producer": true}
			for k := range pkg {
				if !allowedPkg[k] {
					fail("pap.package.unknown-field", "manifest.package", "unknown field: "+k)
				}
			}
			if id, ok3 := pkg["id"].(string); !ok3 || id == "" {
				fail("pap.package.schema", "manifest.package", "package.id required nonempty")
			} else if len(id) > 512 {
				fail("pap.package.schema", "manifest.package", "package.id too long")
			}
			if t, ok3 := pkg["title"]; ok3 {
				s, ok4 := t.(string)
				if !ok4 || len(s) > 512 {
					fail("pap.package.schema", "manifest.package", "invalid title")
				}
			}
			if ca, ok3 := pkg["createdAt"]; ok3 {
				s, ok4 := ca.(string)
				if !ok4 || !isRFC3339(s) {
					fail("pap.package.schema", "manifest.package", "invalid createdAt")
				}
			}
			if pr, ok3 := pkg["producer"]; ok3 {
				pm, ok4 := pr.(map[string]any)
				if !ok4 {
					fail("pap.package.schema", "manifest.package.producer", "producer must be object")
				} else {
					allowedProd := map[string]bool{"name": true, "version": true}
					for k := range pm {
						if !allowedProd[k] {
							fail("pap.package.unknown-field", "manifest.package.producer", "unknown field: "+k)
						}
					}
					nm, _ := pm["name"].(string)
					ver, _ := pm["version"].(string)
					if _, ok5 := pm["name"]; !ok5 || nm == "" || len(nm) > 256 {
						fail("pap.package.schema", "manifest.package.producer", "invalid producer.name")
					}
					if _, ok5 := pm["version"]; !ok5 || ver == "" || len(ver) > 128 {
						fail("pap.package.schema", "manifest.package.producer", "invalid producer.version")
					}
					if len(pm) != 2 {
						// both required if producer present
						if _, ok5 := pm["name"]; !ok5 {
							fail("pap.package.schema", "manifest.package.producer", "missing name")
						}
						if _, ok5 := pm["version"]; !ok5 {
							fail("pap.package.schema", "manifest.package.producer", "missing version")
						}
					}
				}
			}
		}
	}

	// subject
	if s, exists := m["subject"]; exists {
		sm, ok3 := s.(map[string]any)
		if !ok3 {
			fail("pap.package.schema", "manifest.subject", "subject must be object")
		} else {
			allowed := map[string]bool{"projectId": true, "revision": true}
			for k := range sm {
				if !allowed[k] {
					fail("pap.package.unknown-field", "manifest.subject", "unknown field: "+k)
				}
			}
			pid, ok4 := sm["projectId"].(string)
			if !ok4 || pid == "" || len(pid) > 512 {
				fail("pap.package.schema", "manifest.subject", "invalid projectId")
			}
			if r, ok4 := sm["revision"]; ok4 {
				sr, ok5 := r.(string)
				if !ok5 || len(sr) > 256 {
					fail("pap.package.schema", "manifest.subject", "invalid revision")
				}
			}
			if _, ok4 := sm["projectId"]; !ok4 {
				fail("pap.package.schema", "manifest.subject", "missing projectId")
			}
		}
	}

	// build
	if b, exists := m["build"]; exists {
		bm, ok3 := b.(map[string]any)
		if !ok3 {
			fail("pap.package.schema", "manifest.build", "build must be object")
		} else {
			allowed := map[string]bool{"engineVersion": true, "manifestVersion": true, "inputDigest": true, "normalizedInputDigest": true, "extensions": true}
			for k := range bm {
				if !allowed[k] {
					fail("pap.package.unknown-field", "manifest.build", "unknown field: "+k)
				}
			}
			if ev, ok4 := bm["engineVersion"]; ok4 {
				s, ok5 := ev.(string)
				if !ok5 || s == "" || len(s) > 128 {
					fail("pap.package.schema", "manifest.build", "invalid engineVersion")
				}
			}
			if mv, ok4 := bm["manifestVersion"]; ok4 {
				s, ok5 := mv.(string)
				if !ok5 || s == "" || len(s) > 64 {
					fail("pap.package.schema", "manifest.build", "invalid manifestVersion")
				}
			}
			if d, ok4 := bm["inputDigest"]; ok4 {
				s, ok5 := d.(string)
				if !ok5 || !matchPattern(`^sha256:[0-9a-f]{64}$`, s) {
					fail("pap.package.schema", "manifest.build", "invalid inputDigest")
				}
			}
			if d, ok4 := bm["normalizedInputDigest"]; ok4 {
				s, ok5 := d.(string)
				if !ok5 || !matchPattern(`^sha256:[0-9a-f]{64}$`, s) {
					fail("pap.package.schema", "manifest.build", "invalid normalizedInputDigest")
				}
			}
			if exts, ok4 := bm["extensions"]; ok4 {
				arr, ok5 := exts.([]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.build", "extensions must be array")
				} else {
					seen := map[string]bool{}
					for _, e := range arr {
						em, ok6 := e.(map[string]any)
						if !ok6 {
							fail("pap.package.schema", "manifest.build.extensions", "extension entry must be object")
							continue
						}
						allowedE := map[string]bool{"kind": true, "id": true, "version": true}
						for k := range em {
							if !allowedE[k] {
								fail("pap.package.unknown-field", "manifest.build.extensions", "unknown field: "+k)
							}
						}
						for _, r := range []string{"kind", "id", "version"} {
							if _, ok7 := em[r]; !ok7 {
								fail("pap.package.schema", "manifest.build.extensions", "missing "+r)
							}
						}
						kind, _ := em["kind"].(string)
						if kind != "profile" && kind != "adapter" && kind != "renderer" && kind != "checker" {
							fail("pap.package.schema", "manifest.build.extensions", "invalid kind")
						}
						id, _ := em["id"].(string)
						if id == "" || len(id) > 256 {
							fail("pap.package.schema", "manifest.build.extensions", "invalid id")
						}
						ver, _ := em["version"].(string)
						if ver == "" || len(ver) > 128 {
							fail("pap.package.schema", "manifest.build.extensions", "invalid version")
						}
						key := kind + "|" + id + "|" + ver
						if seen[key] {
							fail("pap.package.duplicate-id", "manifest.build.extensions", "duplicate extension")
						}
						seen[key] = true
					}
				}
			}
		}
	}

	// artifacts
	arts, ok3 := m["artifacts"].([]any)
	if _, exists := m["artifacts"]; exists {
		if !ok3 {
			fail("pap.package.schema", "manifest.artifacts", "artifacts must be array")
		} else {
			if len(arts) < 1 {
				fail("pap.package.schema", "manifest.artifacts", "artifacts must be nonempty")
			}
			ids := map[string]bool{}
			paths := []string{}
			for i, a := range arts {
				am, ok4 := a.(map[string]any)
				if !ok4 {
					fail("pap.package.schema", "manifest.artifacts", "artifact must be object")
					continue
				}
				allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "bytes": true, "digest": true}
				for k := range am {
					if !allowed[k] {
						fail("pap.package.unknown-field", "manifest.artifacts", "unknown field: "+k)
					}
				}
				for _, r := range []string{"id", "path", "mediaType", "bytes", "digest"} {
					if _, ok5 := am[r]; !ok5 {
						fail("pap.package.schema", "manifest.artifacts", "missing "+r)
					}
				}
				id, _ := am["id"].(string)
				if id == "" || len(id) > 256 {
					fail("pap.package.schema", "manifest.artifacts", "invalid id")
				} else {
					if ids[id] {
						fail("pap.package.duplicate-id", "manifest.artifacts", "duplicate id: "+id)
					}
					ids[id] = true
				}
				path, _ := am["path"].(string)
				if !validPathGrammar(path, limits) {
					fail("pap.package.path-invalid", "manifest.artifacts", "invalid path")
				} else if !strings.HasPrefix(path, "artifacts/") {
					fail("pap.package.schema", "manifest.artifacts", "path must start artifacts/")
				}
				paths = append(paths, path)
				mt, _ := am["mediaType"].(string)
				if mt == "" || len(mt) > 256 {
					fail("pap.package.schema", "manifest.artifacts", "invalid mediaType")
				}
				// bytes integer
				bv, ok5 := am["bytes"]
				if !ok5 {
					fail("pap.package.schema", "manifest.artifacts", "missing bytes")
				} else {
					bi, ok6 := bv.(int64)
					if !ok6 || bi < 0 {
						fail("pap.package.schema", "manifest.artifacts", "invalid bytes")
					}
				}
				dg, _ := am["digest"].(string)
				if !matchPattern(`^sha256:[0-9a-f]{64}$`, dg) {
					fail("pap.package.schema", "manifest.artifacts", "invalid digest")
				}
				_ = i
			}
			// duplicate paths handled globally later
			_ = paths
		}
	}

	// inputs
	if ins, exists := m["inputs"]; exists {
		arr, ok4 := ins.([]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.inputs", "inputs must be array")
		} else {
			ids := map[string]bool{}
			for _, in := range arr {
				im, ok5 := in.(map[string]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.inputs", "input must be object")
					continue
				}
				allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "digest": true, "normalization": true}
				for k := range im {
					if !allowed[k] {
						fail("pap.package.unknown-field", "manifest.inputs", "unknown field: "+k)
					}
				}
				for _, r := range []string{"id", "path", "mediaType", "digest", "normalization"} {
					if _, ok6 := im[r]; !ok6 {
						fail("pap.package.schema", "manifest.inputs", "missing "+r)
					}
				}
				id, _ := im["id"].(string)
				if id == "" || len(id) > 256 {
					fail("pap.package.schema", "manifest.inputs", "invalid id")
				} else {
					if ids[id] {
						fail("pap.package.duplicate-id", "manifest.inputs", "duplicate id")
					}
					ids[id] = true
				}
				path, _ := im["path"].(string)
				if !validPathGrammar(path, limits) || !strings.HasPrefix(path, "inputs/") {
					if !validPathGrammar(path, limits) {
						fail("pap.package.path-invalid", "manifest.inputs", "invalid path")
					} else {
						fail("pap.package.schema", "manifest.inputs", "path must start inputs/")
					}
				}
				mt, _ := im["mediaType"].(string)
				if mt == "" || len(mt) > 256 {
					fail("pap.package.schema", "manifest.inputs", "invalid mediaType")
				}
				dg, _ := im["digest"].(string)
				if !matchPattern(`^sha256:[0-9a-f]{64}$`, dg) {
					fail("pap.package.schema", "manifest.inputs", "invalid digest")
				}
				norm, _ := im["normalization"].(string)
				if norm != "lf" && norm != "none" {
					fail("pap.package.schema", "manifest.inputs", "invalid normalization")
				}
			}
		}
	}

	// sources
	if srcs, exists := m["sources"]; exists {
		arr, ok4 := srcs.([]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.sources", "sources must be array")
		} else {
			ids := map[string]bool{}
			for _, s := range arr {
				sm, ok5 := s.(map[string]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.sources", "source must be object")
					continue
				}
				allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "digest": true, "acquiredAt": true, "acquisition": true}
				for k := range sm {
					if !allowed[k] {
						fail("pap.package.unknown-field", "manifest.sources", "unknown field: "+k)
					}
				}
				for _, r := range []string{"id", "mediaType", "digest"} {
					if _, ok6 := sm[r]; !ok6 {
						fail("pap.package.schema", "manifest.sources", "missing "+r)
					}
				}
				id, _ := sm["id"].(string)
				if id == "" || len(id) > 256 {
					fail("pap.package.schema", "manifest.sources", "invalid id")
				} else {
					if ids[id] {
						fail("pap.package.duplicate-id", "manifest.sources", "duplicate id")
					}
					ids[id] = true
				}
				if path, ok6 := sm["path"]; ok6 {
					ps, ok7 := path.(string)
					if !ok7 || !validPathGrammar(ps, limits) || !strings.HasPrefix(ps, "sources/") {
						if !ok7 || !validPathGrammar(ps, limits) {
							fail("pap.package.path-invalid", "manifest.sources", "invalid path")
						} else {
							fail("pap.package.schema", "manifest.sources", "path must start sources/")
						}
					}
				}
				mt, _ := sm["mediaType"].(string)
				if mt == "" || len(mt) > 256 {
					fail("pap.package.schema", "manifest.sources", "invalid mediaType")
				}
				dg, _ := sm["digest"].(string)
				if !matchPattern(`^sha256:[0-9a-f]{64}$`, dg) {
					fail("pap.package.schema", "manifest.sources", "invalid digest")
				}
				if aa, ok6 := sm["acquiredAt"]; ok6 {
					s, ok7 := aa.(string)
					if !ok7 || !isRFC3339(s) {
						fail("pap.package.schema", "manifest.sources", "invalid acquiredAt")
					}
				}
				if acq, ok6 := sm["acquisition"]; ok6 {
					am, ok7 := acq.(map[string]any)
					if !ok7 {
						fail("pap.package.schema", "manifest.sources", "acquisition must be object")
					} else {
						allowedA := map[string]bool{"method": true, "uri": true, "revision": true}
						for k := range am {
							if !allowedA[k] {
								fail("pap.package.unknown-field", "manifest.sources.acquisition", "unknown field: "+k)
							}
						}
						if mth, ok8 := am["method"].(string); !ok8 || mth == "" || len(mth) > 128 {
							fail("pap.package.schema", "manifest.sources", "invalid acquisition.method")
						}
						if uri, ok8 := am["uri"]; ok8 {
							s, ok9 := uri.(string)
							if !ok9 || len(s) > 2048 {
								fail("pap.package.schema", "manifest.sources", "invalid acquisition.uri")
							}
						}
						if rev, ok8 := am["revision"]; ok8 {
							s, ok9 := rev.(string)
							if !ok9 || len(s) > 512 {
								fail("pap.package.schema", "manifest.sources", "invalid acquisition.revision")
							}
						}
						if _, ok8 := am["method"]; !ok8 {
							fail("pap.package.schema", "manifest.sources", "missing acquisition.method")
						}
					}
				}
			}
		}
	}

	// claims
	if cl, exists := m["claims"]; exists {
		cm, ok4 := cl.(map[string]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.claims", "claims must be object")
		} else {
			allowed := map[string]bool{"provenance": true, "relations": true, "producerReport": true, "reviews": true}
			for k := range cm {
				if !allowed[k] {
					fail("pap.package.unknown-field", "manifest.claims", "unknown field: "+k)
				}
			}
			for kind, v := range cm {
				vm, ok5 := v.(map[string]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.claims", "claim ref must be object")
					continue
				}
				allowedR := map[string]bool{"path": true, "digest": true}
				for k := range vm {
					if !allowedR[k] {
						fail("pap.package.unknown-field", "manifest.claims", "unknown field: "+k)
					}
				}
				for _, r := range []string{"path", "digest"} {
					if _, ok6 := vm[r]; !ok6 {
						fail("pap.package.schema", "manifest.claims", "missing "+r)
					}
				}
				path, _ := vm["path"].(string)
				if !validPathGrammar(path, limits) || !strings.HasPrefix(path, "claims/") {
					if !validPathGrammar(path, limits) {
						fail("pap.package.path-invalid", "manifest.claims", "invalid path")
					} else {
						fail("pap.package.schema", "manifest.claims", "path must start claims/")
					}
				}
				dg, _ := vm["digest"].(string)
				if !matchPattern(`^sha256:[0-9a-f]{64}$`, dg) {
					fail("pap.package.schema", "manifest.claims", "invalid digest")
				}
				_ = kind
			}
		}
	}

	// profile
	if pr, exists := m["profile"]; exists {
		pm, ok4 := pr.(map[string]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.profile", "profile must be object")
		} else {
			allowed := map[string]bool{"id": true, "version": true, "closureDigest": true}
			for k := range pm {
				if !allowed[k] {
					fail("pap.package.unknown-field", "manifest.profile", "unknown field: "+k)
				}
			}
			for _, r := range []string{"id", "version"} {
				if _, ok5 := pm[r]; !ok5 {
					fail("pap.package.schema", "manifest.profile", "missing "+r)
				}
			}
			id, _ := pm["id"].(string)
			if id == "" || len(id) > 256 {
				fail("pap.package.schema", "manifest.profile", "invalid id")
			}
			ver, _ := pm["version"].(string)
			if ver == "" || len(ver) > 128 {
				fail("pap.package.schema", "manifest.profile", "invalid version")
			}
			if cd, ok5 := pm["closureDigest"]; ok5 {
				s, ok6 := cd.(string)
				if !ok6 || !matchPattern(`^sha256:[0-9a-f]{64}$`, s) {
					fail("pap.package.schema", "manifest.profile", "invalid closureDigest")
				}
			}
		}
	}

	// checkSpecs
	cs, exists := m["checkSpecs"]
	if exists {
		arr, ok4 := cs.([]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.checkSpecs", "checkSpecs must be array")
		} else {
			if len(arr) < 1 {
				fail("pap.package.schema", "manifest.checkSpecs", "must be nonempty")
			}
			ids := map[string]bool{}
			for _, c := range arr {
				cm, ok5 := c.(map[string]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.checkSpecs", "entry must be object")
					continue
				}
				allowed := map[string]bool{"id": true, "version": true, "required": true}
				for k := range cm {
					if !allowed[k] {
						fail("pap.package.unknown-field", "manifest.checkSpecs", "unknown field: "+k)
					}
				}
				for _, r := range []string{"id", "version"} {
					if _, ok6 := cm[r]; !ok6 {
						fail("pap.package.schema", "manifest.checkSpecs", "missing "+r)
					}
				}
				id, _ := cm["id"].(string)
				if !matchPattern(`^pap\.check\.[a-z0-9-]+/[0-9]+$`, id) {
					fail("pap.package.schema", "manifest.checkSpecs", "invalid check id")
				} else {
					if ids[id] {
						fail("pap.package.duplicate-id", "manifest.checkSpecs", "duplicate check id")
					}
					ids[id] = true
					// version suffix
					parts := strings.Split(id, "/")
					suffix := ""
					if len(parts) == 2 {
						suffix = parts[1]
					}
					ver, _ := cm["version"].(string)
					if ver != suffix {
						fail("pap.package.schema", "manifest.checkSpecs", "version mismatch")
					}
				}
				ver, _ := cm["version"].(string)
				if !matchPattern(`^(0|[1-9][0-9]*)$`, ver) {
					fail("pap.package.schema", "manifest.checkSpecs", "invalid version")
				}
				if r, ok6 := cm["required"]; ok6 {
					if _, ok7 := r.(bool); !ok7 {
						fail("pap.package.schema", "manifest.checkSpecs", "required must be bool")
					}
				}
			}
		}
	}

	// extensions
	if ext, exists := m["extensions"]; exists {
		em, ok4 := ext.(map[string]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.extensions", "extensions must be object")
		} else {
			for key, v := range em {
				if !matchPattern(`^[a-z0-9]+(\.[a-z0-9-]+)+$`, key) {
					fail("pap.package.schema", "manifest.extensions", "invalid extension key")
				}
				vm, ok5 := v.(map[string]any)
				if !ok5 {
					fail("pap.package.schema", "manifest.extensions", "extension must be object")
					continue
				}
				allowed := map[string]bool{"version": true, "critical": true, "data": true}
				for k := range vm {
					if !allowed[k] {
						fail("pap.package.unknown-field", "manifest.extensions", "unknown field: "+k)
					}
				}
				for _, r := range []string{"version", "critical"} {
					if _, ok6 := vm[r]; !ok6 {
						fail("pap.package.schema", "manifest.extensions", "missing "+r)
					}
				}
				ver, _ := vm["version"].(string)
				if ver == "" || len(ver) > 128 {
					fail("pap.package.schema", "manifest.extensions", "invalid version")
				}
				crit, ok6 := vm["critical"].(bool)
				if !ok6 {
					fail("pap.package.schema", "manifest.extensions", "critical must be bool")
				}
				// unknown extension handling
				if crit {
					warn("pap.extension.critical-unsupported", "manifest.extensions", "critical unknown extension")
				} else {
					info("pap.extension.ignored", "manifest.extensions", "non-critical unknown extension ignored")
				}
				if _, ok6 := vm["data"]; ok6 {
					if _, ok7 := vm["data"].(map[string]any); !ok7 {
						fail("pap.package.schema", "manifest.extensions", "data must be object")
					}
				}
			}
		}
	}

	// requiredFeatures
	if rf, exists := m["requiredFeatures"]; exists {
		arr, ok4 := rf.([]any)
		if !ok4 {
			fail("pap.package.schema", "manifest.requiredFeatures", "must be array")
		} else {
			seen := map[string]bool{}
			for _, f := range arr {
				s, ok5 := f.(string)
				if !ok5 || !matchPattern(`^pap\.[a-z0-9.-]+$`, s) {
					fail("pap.package.schema", "manifest.requiredFeatures", "invalid feature")
					continue
				}
				if seen[s] {
					fail("pap.package.schema", "manifest.requiredFeatures", "duplicate feature")
				}
				seen[s] = true
				// unknown feature
				warn("pap.feature.unsupported", "manifest.requiredFeatures", "unsupported feature: "+s)
			}
		}
	}

	// cross-field: duplicate ids across? done per class.
	// duplicate paths global
	allPaths := []string{}
	addPaths := func(arr []any, field string) {
		for _, e := range arr {
			em, ok5 := e.(map[string]any)
			if !ok5 {
				continue
			}
			if p, ok6 := em["path"].(string); ok6 {
				allPaths = append(allPaths, p)
			}
		}
	}
	if arts, ok4 := m["artifacts"].([]any); ok4 {
		addPaths(arts, "artifacts")
	}
	if ins, ok4 := m["inputs"].([]any); ok4 {
		addPaths(ins, "inputs")
	}
	if srcs, ok4 := m["sources"].([]any); ok4 {
		for _, s := range srcs {
			sm, ok5 := s.(map[string]any)
			if !ok5 {
				continue
			}
			if p, ok6 := sm["path"].(string); ok6 {
				allPaths = append(allPaths, p)
			}
		}
	}
	if cl, ok4 := m["claims"].(map[string]any); ok4 {
		for _, v := range cl {
			vm, ok5 := v.(map[string]any)
			if !ok5 {
				continue
			}
			if p, ok6 := vm["path"].(string); ok6 {
				allPaths = append(allPaths, p)
			}
		}
	}

	// manifest self-reference
	for _, p := range allPaths {
		if p == "assurance-package.json" {
			fail("pap.package.manifest-self-reference", "manifest", "manifest declares itself")
		}
	}

	// duplicate / case collision
	seenPath := map[string]bool{}
	seenCase := map[string]bool{}
	for _, p := range allPaths {
		if p == "" {
			continue
		}
		if seenPath[p] {
			fail("pap.package.path-duplicate", "manifest", "duplicate path: "+p)
		}
		seenPath[p] = true
		lc := strings.ToLower(p)
		if seenCase[lc] {
			fail("pap.package.path-duplicate", "manifest", "case-colliding path: "+p)
		}
		seenCase[lc] = true
	}

	// path grammar violations reported path-invalid (already for each field, but global check)
	for _, p := range allPaths {
		if p == "" {
			continue
		}
		if !validPathGrammar(p, limits) {
			fail("pap.package.path-invalid", "manifest", "invalid path: "+p)
		}
	}

	// duplicate ids across checkSpecs already; duplicate artifact/source/input ids already.
	// unique claim paths: if two claim kinds same path -> duplicate path catches.

	// empty required check set? Not schema failure; handled later.

	_ = sort.Strings
	_ = warn
	_ = info
	_ = fmt.Sprintf
	return diags, ok
}

func matchPattern(pat string, s string) bool {
	// simple regex via Go regexp? import. We'll use manual? Use regexp.
	import_regexp_placeholder := 0
	_ = import_regexp_placeholder
	return regexpMatch(pat, s)
}

func isRFC3339(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func regexpMatch(pat, s string) bool {
	re, err := regexp.Compile(pat)
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

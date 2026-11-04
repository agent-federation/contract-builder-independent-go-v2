package papverifier

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type Diagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Scope    string `json:"scope"`
	Message  string `json:"message"`
}
type Limitation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type ArtifactIdentity struct {
	ID       string  `json:"id"`
	Declared string  `json:"declared"`
	Computed *string `json:"computed"`
}
type SourceIdentity struct {
	ID       string  `json:"id"`
	Declared string  `json:"declared"`
	Computed *string `json:"computed"`
}

type PackageRead struct {
	Root            string
	ManifestBytes   []byte
	ManifestValue   any
	ManifestParsed  bool
	ParseError      string
	Diagnostics     []Diagnostic
	Limitations     []Limitation
	PackageIdentity *string
	PapVersion      *string
	// integrity
	IntegrityPackage    string
	IntegrityArtifacts  string
	SourcesIntegrity    string
	SourcesAvailability string
	// identities
	Artifacts              []ArtifactIdentity
	Sources                []SourceIdentity
	NormalizedInputDigest  *string
	ExtensionClosureDigest *string
	// payloads read state
	ArtifactBytesMatch bool
	MissingManifest    bool
	// declared paths
	DeclaredPaths []string
	// resource limit tracking
	LimitExceeded bool
	CoverageFull  bool
	// manifest schema valid?
	SchemaValid bool
	// cross-field
	DuplicateIDs bool
	// check specs
	CheckSpecs []struct {
		ID       string
		Version  string
		Required bool
	}
	// raw manifest map
	ManifestMap map[string]any
	// claims present
	HasProducerReport bool
	// undeclared scan complete
	UndeclaredScanComplete bool
	// total bytes read
	TotalPayloadBytes int64
	// version unsupported flags
	UnsupportedVersion bool
	NewerMinor         bool
	// required features
	RequiredFeatures []string
	// extensions
	Extensions map[string]any
	// claims digests
	ClaimDigests map[string]string // kind -> declared
	// claim files read bytes
	ClaimBytes map[string][]byte
	// profile closure
	ProfileClosureDigest *string
	// sources list for ids
	SourceIDs   []string
	ArtifactIDs []string
	InputIDs    []string
	// inputs normalized digest computed?
	InputsPresent bool
}

const (
	manifestByteLimit = 1 * 1024 * 1024
	payloadFileLimit  = 4096
	fileByteLimit     = 256 * 1024 * 1024
	totalPayloadLimit = 1 * 1024 * 1024 * 1024
	jsonNestingLimit  = 64
	jsonStringLimit   = 16 * 1024 * 1024
)

func addDiag(pr *PackageRead, code, severity, scope, msg string) {
	pr.Diagnostics = append(pr.Diagnostics, Diagnostic{Code: code, Severity: severity, Scope: scope, Message: msg})
}
func addLimit(pr *PackageRead, code, detail string) {
	pr.Limitations = append(pr.Limitations, Limitation{Code: code, Detail: detail})
}

func diagSev(code string) string {
	// default error for package codes; adjust a few
	switch code {
	case "pap.package.undeclared-file", "pap.package.undeclared-scan-incomplete",
		"pap.package.empty-check-specs", "pap.extension.ignored":
		return "warning"
	case "pap.feature.unsupported", "pap.extension.critical-unsupported",
		"pap.compat.version-unsupported", "pap.compat.minor-newer",
		"pap.check.unsupported", "pap.check.not-evaluated":
		return "warning"
	}
	return "error"
}

// resolvePackageRoot resolves symlink once.
func resolvePackageRoot(pkg string) (string, error) {
	info, err := os.Lstat(pkg)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(pkg)
		if err != nil {
			return "", err
		}
		info, err = os.Stat(resolved)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", fmt.Errorf("not directory")
		}
		return resolved, nil
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not directory")
	}
	return pkg, nil
}

func readPackage(pkgArg string) (*PackageRead, int, error) {
	// returns exit code for immediate failures (74/64) if root missing/not dir
	pr := &PackageRead{
		IntegrityPackage:       "",
		IntegrityArtifacts:     "NOT_EVALUATED",
		SourcesIntegrity:       "NOT_EVALUATED",
		SourcesAvailability:    "NOT_APPLICABLE",
		CoverageFull:           true,
		UndeclaredScanComplete: true,
		ClaimDigests:           map[string]string{},
		ClaimBytes:             map[string][]byte{},
	}
	root, err := resolvePackageRoot(pkgArg)
	if err != nil {
		// missing
		if os.IsNotExist(err) {
			return nil, 74, fmt.Errorf("pap.package.not-found")
		}
		// not directory? treat usage? We'll let caller handle: if err not not-exist, maybe 64
		// distinguish: if path exists but not dir
		if info, _ := os.Stat(pkgArg); info != nil && !info.IsDir() {
			return nil, 64, fmt.Errorf("pap.cli.usage")
		}
		return nil, 74, fmt.Errorf("pap.package.not-found")
	}
	// ensure directory
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return nil, 64, fmt.Errorf("pap.cli.usage")
	}
	pr.Root = root

	// read manifest
	manifestPath := filepath.Join(root, "assurance-package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		// manifest cannot be read -> pap.package.io, FAIL report
		pr.MissingManifest = true
		addDiag(pr, "pap.package.io", "error", "package", "manifest unreadable")
		pr.IntegrityPackage = "FAIL"
		pr.IntegrityArtifacts = "NOT_EVALUATED"
		pr.PackageIdentity = nil
		pr.CoverageFull = false
		pr.UndeclaredScanComplete = false
		return pr, 0, nil
	}
	if len(data) > manifestByteLimit {
		// limit exceeded prevents manifest parse -> FAIL
		pr.ManifestBytes = nil
		addDiag(pr, "pap.package.limit-exceeded", "error", "package", "manifest byte limit")
		pr.IntegrityPackage = "FAIL"
		pr.PackageIdentity = nil
		pr.CoverageFull = false
		return pr, 0, nil
	}
	pr.ManifestBytes = data

	// parse JSON strict
	val, err := parseStrictJSON(data, jsonNestingLimit, jsonStringLimit)
	if err != nil {
		code := "pap.package.manifest-json"
		if strings.Contains(err.Error(), "duplicate key") {
			code = "pap.package.duplicate-key"
		}
		addDiag(pr, code, "error", "package", err.Error())
		pr.IntegrityPackage = "FAIL"
		pr.PackageIdentity = nil
		pr.CoverageFull = false
		// maybe undeclared scan still? We'll skip
		return pr, 0, nil
	}
	pr.ManifestValue = val
	pr.ManifestParsed = true
	m, ok := val.(map[string]any)
	if !ok {
		addDiag(pr, "pap.package.manifest-json", "error", "package", "manifest not object")
		pr.IntegrityPackage = "FAIL"
		pr.PackageIdentity = nil
		pr.CoverageFull = false
		return pr, 0, nil
	}
	pr.ManifestMap = m

	// canonicalize for identity (may fail on integer range etc.)
	canon, err := CanonicalJSON(val)
	if err != nil {
		addDiag(pr, "pap.package.manifest-json", "error", "package", err.Error())
		pr.IntegrityPackage = "FAIL"
		pr.PackageIdentity = nil
		pr.CoverageFull = false
		return pr, 0, nil
	}
	id := DomainHash("pap.package.v1", canon)
	pr.PackageIdentity = &id

	// schema validation
	schemaDiags := validateManifestSchema(m, pr)
	if len(schemaDiags) > 0 {
		pr.Diagnostics = append(pr.Diagnostics, schemaDiags...)
		pr.SchemaValid = false
		pr.IntegrityPackage = "FAIL"
	} else {
		pr.SchemaValid = true
	}

	// extract fields
	extractManifest(pr, m)

	// path validation + duplicates
	pathDiags := validatePaths(pr)
	if len(pathDiags) > 0 {
		pr.Diagnostics = append(pr.Diagnostics, pathDiags...)
		pr.IntegrityPackage = "FAIL"
	}

	// version compatibility
	checkVersionCompat(pr)

	// required features
	if len(pr.RequiredFeatures) > 0 {
		for _, f := range pr.RequiredFeatures {
			addDiag(pr, "pap.feature.unsupported", "warning", "package", f)
		}
		// verdict handled later
	}
	// extensions critical
	if pr.Extensions != nil {
		for name, v := range pr.Extensions {
			em, _ := v.(map[string]any)
			crit, _ := em["critical"].(bool)
			// support none -> if critical, unsupported
			if crit {
				addDiag(pr, "pap.extension.critical-unsupported", "warning", "package", name)
			} else {
				addDiag(pr, "pap.extension.ignored", "info", "package", name)
				addLimit(pr, "pap.extension.ignored", name)
			}
		}
	}

	// undeclared scan
	scanDiags, complete := undeclaredScan(pr)
	pr.Diagnostics = append(pr.Diagnostics, scanDiags...)
	pr.UndeclaredScanComplete = complete
	if !complete {
		pr.CoverageFull = false
		addLimit(pr, "pap.package.undeclared-scan-incomplete", "undeclared scan incomplete")
	}

	// read payloads if schema valid? We'll attempt even if schema invalid? For missing manifest etc. For schema invalid, integrity.artifacts NOT_EVALUATED.
	if !pr.SchemaValid {
		pr.IntegrityArtifacts = "NOT_EVALUATED"
		pr.SourcesIntegrity = "NOT_EVALUATED"
		// still maybe undeclared scan done
		return pr, 0, nil
	}

	// read payloads
	readPayloads(pr)

	return pr, 0, nil
}

func extractManifest(pr *PackageRead, m map[string]any) {
	if v, ok := m["papVersion"].(string); ok {
		pr.PapVersion = &v
	}
	// checkSpecs
	if cs, ok := m["checkSpecs"].([]any); ok {
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			id, _ := cm["id"].(string)
			ver, _ := cm["version"].(string)
			req := false
			if r, ok := cm["required"].(bool); ok {
				req = r
			}
			pr.CheckSpecs = append(pr.CheckSpecs, struct {
				ID       string
				Version  string
				Required bool
			}{id, ver, req})
		}
	}
	// required features
	if rf, ok := m["requiredFeatures"].([]any); ok {
		for _, f := range rf {
			if s, ok := f.(string); ok {
				pr.RequiredFeatures = append(pr.RequiredFeatures, s)
			}
		}
	}
	// extensions
	if ext, ok := m["extensions"].(map[string]any); ok {
		pr.Extensions = ext
	}
	// claims
	if claims, ok := m["claims"].(map[string]any); ok {
		for kind, v := range claims {
			cm, _ := v.(map[string]any)
			path, _ := cm["path"].(string)
			dig, _ := cm["digest"].(string)
			pr.ClaimDigests[kind] = dig
			_ = path
		}
	}
	// profile
	if prof, ok := m["profile"].(map[string]any); ok {
		if cd, ok := prof["closureDigest"].(string); ok {
			pr.ProfileClosureDigest = &cd
		}
	}
	// sources ids
	if srcs, ok := m["sources"].([]any); ok {
		for _, s := range srcs {
			sm, _ := s.(map[string]any)
			id, _ := sm["id"].(string)
			pr.SourceIDs = append(pr.SourceIDs, id)
		}
	}
	if arts, ok := m["artifacts"].([]any); ok {
		for _, a := range arts {
			am, _ := a.(map[string]any)
			id, _ := am["id"].(string)
			pr.ArtifactIDs = append(pr.ArtifactIDs, id)
		}
	}
	if ins, ok := m["inputs"].([]any); ok {
		for _, in := range ins {
			im, _ := in.(map[string]any)
			id, _ := im["id"].(string)
			pr.InputIDs = append(pr.InputIDs, id)
		}
	}
}

func validateManifestSchema(m map[string]any, pr *PackageRead) []Diagnostic {
	var diags []Diagnostic
	// required fields
	for _, r := range []string{"papVersion", "package", "artifacts", "checkSpecs"} {
		if _, ok := m[r]; !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "missing " + r})
		}
	}
	// additional properties top-level
	allowedTop := map[string]bool{"papVersion": true, "package": true, "subject": true, "build": true, "artifacts": true, "inputs": true, "sources": true, "claims": true, "profile": true, "checkSpecs": true, "extensions": true, "requiredFeatures": true}
	for k := range m {
		if !allowedTop[k] {
			diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
		}
	}
	// papVersion
	if v, ok := m["papVersion"]; ok {
		s, ok := v.(string)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "papVersion type"})
		} else {
			// pattern
			if !matchPattern(s, `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`) {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "papVersion pattern"})
			}
		}
	}
	// package object
	if v, ok := m["package"]; ok {
		pm, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "package type"})
		} else {
			// additional props
			allowedPkg := map[string]bool{"id": true, "title": true, "createdAt": true, "producer": true}
			for k := range pm {
				if !allowedPkg[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			// required id
			id, ok := pm["id"].(string)
			if !ok || len(id) < 1 || len(id) > 512 {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "package.id"})
			}
			if t, ok := pm["title"].(string); ok {
				if len(t) > 512 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "title"})
				}
			} else if _, ok := pm["title"]; ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "title type"})
			}
			if ca, ok := pm["createdAt"]; ok {
				s, ok := ca.(string)
				if !ok || !validRFC3339(s) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "createdAt"})
				}
			}
			if prod, ok := pm["producer"]; ok {
				pmm, ok := prod.(map[string]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "producer type"})
				} else {
					allowedProd := map[string]bool{"name": true, "version": true}
					for k := range pmm {
						if !allowedProd[k] {
							diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
						}
					}
					nm, _ := pmm["name"].(string)
					if len(nm) < 1 || len(nm) > 256 {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "producer.name"})
					}
					vr, _ := pmm["version"].(string)
					if len(vr) < 1 || len(vr) > 128 {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "producer.version"})
					}
					// required name/version
					if _, ok := pmm["name"]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "producer.name required"})
					}
					if _, ok := pmm["version"]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "producer.version required"})
					}
				}
			}
		}
	}
	// subject optional
	if v, ok := m["subject"]; ok {
		sm, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "subject type"})
		} else {
			allowed := map[string]bool{"projectId": true, "revision": true}
			for k := range sm {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			pid, _ := sm["projectId"].(string)
			if len(pid) < 1 || len(pid) > 512 {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "subject.projectId"})
			}
			if _, ok := sm["projectId"]; !ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "subject.projectId required"})
			}
			if r, ok := sm["revision"].(string); ok {
				if len(r) > 256 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "subject.revision"})
				}
			} else if _, ok := sm["revision"]; ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "subject.revision type"})
			}
		}
	}
	// build optional
	if v, ok := m["build"]; ok {
		bm, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "build type"})
		} else {
			allowed := map[string]bool{"engineVersion": true, "manifestVersion": true, "inputDigest": true, "normalizedInputDigest": true, "extensions": true}
			for k := range bm {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			// digest fields
			for _, df := range []string{"inputDigest", "normalizedInputDigest"} {
				if dv, ok := bm[df]; ok {
					s, ok := dv.(string)
					if !ok || !validDigest(s) {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", df})
					}
				}
			}
			if ev, ok := bm["engineVersion"].(string); ok {
				if len(ev) < 1 || len(ev) > 128 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "engineVersion"})
				}
			} else if _, ok := bm["engineVersion"]; ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "engineVersion type"})
			}
			if mv, ok := bm["manifestVersion"].(string); ok {
				if len(mv) < 1 || len(mv) > 64 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "manifestVersion"})
				}
			} else if _, ok := bm["manifestVersion"]; ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "manifestVersion type"})
			}
			if exts, ok := bm["extensions"]; ok {
				arr, ok := exts.([]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "build.extensions type"})
				} else {
					// uniqueItems check roughly
					seen := map[string]bool{}
					for _, e := range arr {
						em, ok := e.(map[string]any)
						if !ok {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension item"})
							continue
						}
						allowedE := map[string]bool{"kind": true, "id": true, "version": true}
						for k := range em {
							if !allowedE[k] {
								diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
							}
						}
						kind, _ := em["kind"].(string)
						if kind != "profile" && kind != "adapter" && kind != "renderer" && kind != "checker" {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.kind"})
						}
						id, _ := em["id"].(string)
						if len(id) < 1 || len(id) > 256 {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.id"})
						}
						ver, _ := em["version"].(string)
						if len(ver) < 1 || len(ver) > 128 {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.version"})
						}
						for _, r := range []string{"kind", "id", "version"} {
							if _, ok := em[r]; !ok {
								diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension." + r})
							}
						}
						key := kind + "|" + id + "|" + ver
						if seen[key] {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "duplicate extension"})
						}
						seen[key] = true
					}
				}
			}
		}
	}
	// artifacts
	arts, ok := m["artifacts"].([]any)
	if !ok {
		if _, present := m["artifacts"]; present {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifacts type"})
		}
	} else {
		if len(arts) < 1 {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifacts minItems"})
		}
		seenIDs := map[string]bool{}
		seenPaths := map[string]bool{}
		for _, a := range arts {
			am, ok := a.(map[string]any)
			if !ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact item"})
				continue
			}
			allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "bytes": true, "digest": true}
			for k := range am {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			for _, r := range []string{"id", "path", "mediaType", "bytes", "digest"} {
				if _, ok := am[r]; !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact." + r})
				}
			}
			id, _ := am["id"].(string)
			if len(id) < 1 || len(id) > 256 {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact.id"})
			}
			if seenIDs[id] {
				diags = append(diags, Diagnostic{"pap.package.duplicate-id", "error", "package", "artifact id"})
			}
			seenIDs[id] = true
			path, _ := am["path"].(string)
			// path validation
			if !validPathGrammar(path) || !strings.HasPrefix(path, "artifacts/") {
				// don't add here? path-invalid separate; but schema also. We'll let validatePaths handle grammar?
			}
			if seenPaths[strings.ToLower(path)] {
				// duplicate handled in validatePaths
			}
			seenPaths[strings.ToLower(path)] = true
			mt, _ := am["mediaType"].(string)
			if len(mt) < 1 || len(mt) > 256 {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact.mediaType"})
			}
			bv, ok := am["bytes"]
			if !ok {
			} else {
				iv, ok := bv.(int64)
				if !ok || iv < 0 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact.bytes"})
				}
				_ = iv
			}
			dig, _ := am["digest"].(string)
			if !validDigest(dig) {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "artifact.digest"})
			}
		}
	}
	// inputs
	if v, ok := m["inputs"]; ok {
		arr, ok := v.([]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "inputs type"})
		} else {
			seenIDs := map[string]bool{}
			for _, in := range arr {
				im, ok := in.(map[string]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "input item"})
					continue
				}
				allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "digest": true, "normalization": true}
				for k := range im {
					if !allowed[k] {
						diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
					}
				}
				for _, r := range []string{"id", "path", "mediaType", "digest", "normalization"} {
					if _, ok := im[r]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "input." + r})
					}
				}
				id, _ := im["id"].(string)
				if len(id) < 1 || len(id) > 256 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "input.id"})
				}
				if seenIDs[id] {
					diags = append(diags, Diagnostic{"pap.package.duplicate-id", "error", "package", "input id"})
				}
				seenIDs[id] = true
				norm, _ := im["normalization"].(string)
				if norm != "lf" && norm != "none" {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "input.normalization"})
				}
				dig, _ := im["digest"].(string)
				if !validDigest(dig) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "input.digest"})
				}
			}
		}
	}
	// sources
	if v, ok := m["sources"]; ok {
		arr, ok := v.([]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "sources type"})
		} else {
			seenIDs := map[string]bool{}
			for _, s := range arr {
				sm, ok := s.(map[string]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source item"})
					continue
				}
				allowed := map[string]bool{"id": true, "path": true, "mediaType": true, "digest": true, "acquiredAt": true, "acquisition": true}
				for k := range sm {
					if !allowed[k] {
						diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
					}
				}
				for _, r := range []string{"id", "mediaType", "digest"} {
					if _, ok := sm[r]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source." + r})
					}
				}
				id, _ := sm["id"].(string)
				if len(id) < 1 || len(id) > 256 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.id"})
				}
				if seenIDs[id] {
					diags = append(diags, Diagnostic{"pap.package.duplicate-id", "error", "package", "source id"})
				}
				seenIDs[id] = true
				mt, _ := sm["mediaType"].(string)
				if len(mt) < 1 || len(mt) > 256 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.mediaType"})
				}
				dig, _ := sm["digest"].(string)
				if !validDigest(dig) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.digest"})
				}
				if aa, ok := sm["acquiredAt"]; ok {
					s, ok := aa.(string)
					if !ok || !validRFC3339(s) {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.acquiredAt"})
					}
				}
				if acq, ok := sm["acquisition"]; ok {
					am, ok := acq.(map[string]any)
					if !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.acquisition type"})
					} else {
						allowedA := map[string]bool{"method": true, "uri": true, "revision": true}
						for k := range am {
							if !allowedA[k] {
								diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
							}
						}
						method, _ := am["method"].(string)
						if len(method) < 1 || len(method) > 128 {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.acquisition.method"})
						}
						if _, ok := am["method"]; !ok {
							diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "source.acquisition.method required"})
						}
					}
				}
			}
		}
	}
	// claims
	if v, ok := m["claims"]; ok {
		cm, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "claims type"})
		} else {
			allowed := map[string]bool{"provenance": true, "relations": true, "producerReport": true, "reviews": true}
			for k := range cm {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			for kind, ref := range cm {
				rm, ok := ref.(map[string]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "claimRef " + kind})
					continue
				}
				allowedR := map[string]bool{"path": true, "digest": true}
				for k := range rm {
					if !allowedR[k] {
						diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
					}
				}
				for _, r := range []string{"path", "digest"} {
					if _, ok := rm[r]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "claimRef." + r})
					}
				}
				pth, _ := rm["path"].(string)
				if !validPathGrammar(pth) || !strings.HasPrefix(pth, "claims/") {
					// path validation later
				}
				dig, _ := rm["digest"].(string)
				if !validDigest(dig) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "claimRef.digest"})
				}
			}
		}
	}
	// profile
	if v, ok := m["profile"]; ok {
		pm, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile type"})
		} else {
			allowed := map[string]bool{"id": true, "version": true, "closureDigest": true}
			for k := range pm {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			if _, ok := pm["id"]; ok {
				s, _ := pm["id"].(string)
				if len(s) < 1 || len(s) > 256 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile.id"})
				}
			} else {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile.id required"})
			}
			if _, ok := pm["version"]; ok {
				s, _ := pm["version"].(string)
				if len(s) < 1 || len(s) > 128 {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile.version"})
				}
			} else {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile.version required"})
			}
			if cd, ok := pm["closureDigest"]; ok {
				s, _ := cd.(string)
				if !validDigest(s) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "profile.closureDigest"})
				}
			}
		}
	}
	// checkSpecs
	cs, ok := m["checkSpecs"].([]any)
	if !ok {
		if _, present := m["checkSpecs"]; present {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpecs type"})
		}
	} else {
		if len(cs) < 1 {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpecs minItems"})
		}
		seenIDs := map[string]bool{}
		for _, c := range cs {
			cm, ok := c.(map[string]any)
			if !ok {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec item"})
				continue
			}
			allowed := map[string]bool{"id": true, "version": true, "required": true}
			for k := range cm {
				if !allowed[k] {
					diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
				}
			}
			for _, r := range []string{"id", "version"} {
				if _, ok := cm[r]; !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec." + r})
				}
			}
			id, _ := cm["id"].(string)
			if !validCheckID(id) {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec.id"})
			}
			ver, _ := cm["version"].(string)
			if !matchPattern(ver, `^(0|[1-9][0-9]*)$`) {
				diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec.version"})
			}
			// cross-field version suffix
			// extract suffix
			if id != "" && ver != "" {
				// id ends with /version
				parts := strings.Split(id, "/")
				if len(parts) == 2 {
					if parts[1] != ver {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec.version suffix mismatch"})
					}
				}
			}
			if seenIDs[id] {
				diags = append(diags, Diagnostic{"pap.package.duplicate-id", "error", "package", "check id"})
			}
			seenIDs[id] = true
			if req, ok := cm["required"]; ok {
				if _, ok := req.(bool); !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "checkSpec.required type"})
				}
			}
		}
	}
	// extensions
	if v, ok := m["extensions"]; ok {
		em, ok := v.(map[string]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extensions type"})
		} else {
			for name, ev := range em {
				if !matchPattern(name, `^[a-z0-9]+(\.[a-z0-9-]+)+$`) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension name"})
				}
				evm, ok := ev.(map[string]any)
				if !ok {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension value"})
					continue
				}
				allowed := map[string]bool{"version": true, "critical": true, "data": true}
				for k := range evm {
					if !allowed[k] {
						diags = append(diags, Diagnostic{"pap.package.unknown-field", "error", "package", k})
					}
				}
				for _, r := range []string{"version", "critical"} {
					if _, ok := evm[r]; !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension." + r})
					}
				}
				if ver, ok := evm["version"].(string); ok {
					if len(ver) < 1 || len(ver) > 128 {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.version"})
					}
				} else {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.version type"})
				}
				if crit, ok := evm["critical"].(bool); !ok {
					_ = crit
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.critical type"})
				}
				if data, ok := evm["data"]; ok {
					if _, ok := data.(map[string]any); !ok {
						diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "extension.data type"})
					}
				}
			}
		}
	}
	// requiredFeatures
	if v, ok := m["requiredFeatures"]; ok {
		arr, ok := v.([]any)
		if !ok {
			diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "requiredFeatures type"})
		} else {
			seen := map[string]bool{}
			for _, f := range arr {
				s, ok := f.(string)
				if !ok || !matchPattern(s, `^pap\.[a-z0-9.-]+$`) {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "requiredFeature item"})
				}
				if seen[s] {
					diags = append(diags, Diagnostic{"pap.package.schema", "error", "package", "requiredFeatures unique"})
				}
				seen[s] = true
			}
		}
	}

	// cross-field invariants: duplicate ids across? artifact/source/input ids unique within class already.
	// duplicate paths global (case-insensitive) handled in validatePaths.
	// checkSpecs version suffix handled.

	// empty check specs? If no required check, empty-check-specs is diagnostic but schema valid. Handle later.

	return diags
}

func validatePaths(pr *PackageRead) []Diagnostic {
	var diags []Diagnostic
	m := pr.ManifestMap
	// collect declared path entries
	type entry struct {
		class string
		path  string
	}
	var entries []entry
	add := func(class, path string) { entries = append(entries, entry{class, path}) }

	if arts, ok := m["artifacts"].([]any); ok {
		for _, a := range arts {
			am, _ := a.(map[string]any)
			add("artifacts", asString(am["path"]))
		}
	}
	if ins, ok := m["inputs"].([]any); ok {
		for _, in := range ins {
			im, _ := in.(map[string]any)
			add("inputs", asString(im["path"]))
		}
	}
	if srcs, ok := m["sources"].([]any); ok {
		for _, s := range srcs {
			sm, _ := s.(map[string]any)
			if p, ok := sm["path"].(string); ok {
				add("sources", p)
			}
		}
	}
	if claims, ok := m["claims"].(map[string]any); ok {
		for _, ref := range claims {
			rm, _ := ref.(map[string]any)
			add("claims", asString(rm["path"]))
		}
	}

	// path grammar + root prefix
	seenCase := map[string]bool{}
	for _, e := range entries {
		p := e.path
		// grammar
		if !validPathGrammar(p) {
			diags = append(diags, Diagnostic{"pap.package.path-invalid", "error", "package", p})
			continue
		}
		// root prefix
		rootPrefix := e.class + "/"
		// claims root claims/, sources sources/, etc.
		if e.class == "artifacts" && !strings.HasPrefix(p, "artifacts/") {
			diags = append(diags, Diagnostic{"pap.package.path-invalid", "error", "package", p})
		}
		if e.class == "inputs" && !strings.HasPrefix(p, "inputs/") {
			diags = append(diags, Diagnostic{"pap.package.path-invalid", "error", "package", p})
		}
		if e.class == "sources" && !strings.HasPrefix(p, "sources/") {
			diags = append(diags, Diagnostic{"pap.package.path-invalid", "error", "package", p})
		}
		if e.class == "claims" && !strings.HasPrefix(p, "claims/") {
			diags = append(diags, Diagnostic{"pap.package.path-invalid", "error", "package", p})
		}
		_ = rootPrefix
		// case collision duplicate
		lc := strings.ToLower(p)
		if seenCase[lc] {
			diags = append(diags, Diagnostic{"pap.package.path-duplicate", "error", "package", p})
		}
		seenCase[lc] = true
	}
	// manifest self-reference
	for _, e := range entries {
		if e.path == "assurance-package.json" {
			diags = append(diags, Diagnostic{"pap.package.manifest-self-reference", "error", "package", e.path})
		}
	}
	// duplicate exact paths also case-insensitive already; exact duplicates caught by case map? exact same lower catches.
	return diags
}

func validPathGrammar(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	segs := strings.Split(p, "/")
	if len(segs) < 1 || len(segs) > 16 {
		return false
	}
	if len(p) > 255 {
		return false
	}
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		if len(seg) > 255 {
			return false
		}
		for _, r := range seg {
			if !(unicode.Is(unicode.ASCII_Hex_Digit, r) || r == '.' || r == '_' || r == '-') {
				// allowed letters/digits
				if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
					return false
				}
				if r == '.' || r == '_' || r == '-' {
					continue
				}
			}
		}
	}
	// ASCII only already by char checks
	return true
}

func validDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	hexpart := s[7:]
	if len(hexpart) != 64 {
		return false
	}
	for _, c := range hexpart {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validCheckID(s string) bool {
	// ^pap\.check\.[a-z0-9-]+/[0-9]+$
	if !strings.HasPrefix(s, "pap.check.") {
		return false
	}
	rest := s[len("pap.check."):]
	idx := strings.LastIndex(rest, "/")
	if idx < 0 {
		return false
	}
	left := rest[:idx]
	right := rest[idx+1:]
	if left == "" || right == "" {
		return false
	}
	for _, c := range left {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	for _, c := range right {
		if !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func checkVersionCompat(pr *PackageRead) {
	if pr.PapVersion == nil {
		return
	}
	v := *pr.PapVersion
	// supported 0.1
	if v == "0.1" {
		return
	}
	// parse
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		pr.UnsupportedVersion = true
		addDiag(pr, "pap.compat.version-unsupported", "warning", "package", v)
		return
	}
	// major
	if parts[0] != "0" {
		pr.UnsupportedVersion = true
		addDiag(pr, "pap.compat.version-unsupported", "warning", "package", v)
		return
	}
	// minor
	if parts[1] == "1" {
		return
	}
	// newer minor?
	// compare numeric
	if parts[1] > "1" {
		// could be newer
		pr.NewerMinor = true
		addDiag(pr, "pap.compat.minor-newer", "warning", "package", v)
	} else {
		pr.UnsupportedVersion = true
		addDiag(pr, "pap.compat.version-unsupported", "warning", "package", v)
	}
}

func undeclaredScan(pr *PackageRead) ([]Diagnostic, bool) {
	var diags []Diagnostic
	root := pr.Root
	// collect declared set
	declared := map[string]bool{}
	m := pr.ManifestMap
	addDeclared := func(p string) { declared[strings.ToLower(p)] = true }
	if arts, ok := m["artifacts"].([]any); ok {
		for _, a := range arts {
			am, _ := a.(map[string]any)
			addDeclared(asString(am["path"]))
		}
	}
	if ins, ok := m["inputs"].([]any); ok {
		for _, in := range ins {
			im, _ := in.(map[string]any)
			addDeclared(asString(im["path"]))
		}
	}
	if srcs, ok := m["sources"].([]any); ok {
		for _, s := range srcs {
			sm, _ := s.(map[string]any)
			if p, ok := sm["path"].(string); ok {
				addDeclared(p)
			}
		}
	}
	if claims, ok := m["claims"].(map[string]any); ok {
		for _, ref := range claims {
			rm, _ := ref.(map[string]any)
			addDeclared(asString(rm["path"]))
		}
	}

	// walk
	complete := true
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			complete = false
			return filepath.SkipDir
		}
		if path == root {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "assurance-package.json" {
			return nil
		}
		if d.IsDir() {
			// check symlink dir? WalkDir doesn't follow symlinks by default
			return nil
		}
		info, err := d.Info()
		if err != nil {
			complete = false
			return nil
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			// not regular; skip
			return nil
		}
		if !mode.IsRegular() {
			return nil
		}
		// if declared, skip
		if declared[strings.ToLower(rel)] {
			return nil
		}
		// otherwise undeclared file (only consider under known roots? RFC: present regular file under artifacts/inputs/sources/claims/signatures)
		// We'll report any undeclared regular file except maybe top-level? RFC says package must not contain nested manifest; undeclared file warning.
		diags = append(diags, Diagnostic{"pap.package.undeclared-file", "warning", "package", rel})
		return nil
	})
	if err != nil {
		complete = false
	}
	// if any directory unreadable, complete false
	_ = err
	return diags, complete
}

func readPayloads(pr *PackageRead) {
	m := pr.ManifestMap
	root := pr.Root

	// check total declared count
	totalDeclared := 0
	countByClass := map[string]int{}
	for _, c := range []string{"artifacts", "inputs", "sources"} {
		if arr, ok := m[c].([]any); ok {
			totalDeclared += len(arr)
			countByClass[c] = len(arr)
		}
	}
	if claims, ok := m["claims"].(map[string]any); ok {
		totalDeclared += len(claims)
		countByClass["claims"] = len(claims)
	}
	if totalDeclared > payloadFileLimit {
		pr.LimitExceeded = true
		addDiag(pr, "pap.package.limit-exceeded", "error", "package", "payload file count")
		pr.CoverageFull = false
		// read none
		pr.IntegrityArtifacts = "NOT_EVALUATED"
		pr.SourcesIntegrity = "NOT_EVALUATED"
		// set computed nulls
		// artifacts
		if arts, ok := m["artifacts"].([]any); ok {
			for _, a := range arts {
				am, _ := a.(map[string]any)
				pr.Artifacts = append(pr.Artifacts, ArtifactIdentity{ID: asString(am["id"]), Declared: asString(am["digest"]), Computed: nil})
			}
		}
		if srcs, ok := m["sources"].([]any); ok {
			for _, s := range srcs {
				sm, _ := s.(map[string]any)
				pr.Sources = append(pr.Sources, SourceIdentity{ID: asString(sm["id"]), Declared: asString(sm["digest"]), Computed: nil})
			}
		}
		return
	}

	// read artifacts
	arts, _ := m["artifacts"].([]any)
	artifactMismatch := false
	artifactMissing := false
	for _, a := range arts {
		am, _ := a.(map[string]any)
		id := asString(am["id"])
		path := asString(am["path"])
		declaredDigest := asString(am["digest"])
		declaredBytes := int64(0)
		if bv, ok := am["bytes"].(int64); ok {
			declaredBytes = bv
		}
		pr.Artifacts = append(pr.Artifacts, ArtifactIdentity{ID: id, Declared: declaredDigest, Computed: nil})
		last := len(pr.Artifacts) - 1

		// per-file limit check
		if err := checkFileLimits(pr, path); err != nil {
			// limit exceeded
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", err.Error())
			pr.CoverageFull = false
			// stop reading this and rest? We'll break out of all by setting a flag
			pr.Artifacts[last].Computed = nil
			// mark remaining artifacts null
			for i := last + 1; i < len(arts); i++ {
				am2, _ := arts[i].(map[string]any)
				pr.Artifacts = append(pr.Artifacts, ArtifactIdentity{ID: asString(am2["id"]), Declared: asString(am2["digest"]), Computed: nil})
			}
			// skip sources/inputs/claims
			pr.IntegrityArtifacts = "NOT_EVALUATED"
			pr.SourcesIntegrity = "NOT_EVALUATED"
			pr.SourcesAvailability = "NOT_EVALUATED"
			return
		}

		// resolve path safely
		full, safeErr := safeJoin(root, path)
		if safeErr != nil {
			// path escape/symlink
			if strings.Contains(safeErr.Error(), "symlink") {
				addDiag(pr, "pap.package.symlink", "error", "package", path)
			} else if strings.Contains(safeErr.Error(), "non-regular") {
				addDiag(pr, "pap.package.non-regular", "error", "package", path)
			} else {
				addDiag(pr, "pap.package.path-escape", "error", "package", path)
			}
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			artifactMissing = true
			continue
		}
		fi, err := os.Lstat(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			artifactMissing = true
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			addDiag(pr, "pap.package.symlink", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			artifactMissing = true
			continue
		}
		if !fi.Mode().IsRegular() {
			addDiag(pr, "pap.package.non-regular", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			artifactMissing = true
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			artifactMissing = true
			continue
		}
		// per-file byte limit
		if int64(len(data)) > fileByteLimit {
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", path)
			pr.CoverageFull = false
			pr.IntegrityArtifacts = "NOT_EVALUATED"
			// stop
			// mark rest null
			pr.Artifacts[last].Computed = nil
			for i := last + 1; i < len(arts); i++ {
				am2, _ := arts[i].(map[string]any)
				pr.Artifacts = append(pr.Artifacts, ArtifactIdentity{ID: asString(am2["id"]), Declared: asString(am2["digest"]), Computed: nil})
			}
			pr.SourcesIntegrity = "NOT_EVALUATED"
			pr.SourcesAvailability = "NOT_EVALUATED"
			return
		}
		// total payload limit
		if pr.TotalPayloadBytes+int64(len(data)) > totalPayloadLimit {
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", path)
			pr.CoverageFull = false
			pr.IntegrityArtifacts = "NOT_EVALUATED"
			pr.Artifacts[last].Computed = nil
			for i := last + 1; i < len(arts); i++ {
				am2, _ := arts[i].(map[string]any)
				pr.Artifacts = append(pr.Artifacts, ArtifactIdentity{ID: asString(am2["id"]), Declared: asString(am2["digest"]), Computed: nil})
			}
			pr.SourcesIntegrity = "NOT_EVALUATED"
			pr.SourcesAvailability = "NOT_EVALUATED"
			return
		}
		pr.TotalPayloadBytes += int64(len(data))

		computed := DomainHash("pap.artifact.v1", data)
		pr.Artifacts[last].Computed = &computed

		if computed != declaredDigest || int64(len(data)) != declaredBytes {
			artifactMismatch = true
			addDiag(pr, "pap.integrity.artifact-mismatch", "error", "package", path)
		}
	}

	if artifactMissing {
		pr.IntegrityArtifacts = "FAIL"
	} else if artifactMismatch {
		pr.IntegrityArtifacts = "FAIL"
	} else {
		pr.IntegrityArtifacts = "PASS"
	}
	// if no artifacts? schema requires min 1.

	// read sources
	srcs, _ := m["sources"].([]any)
	sourceMismatch := false
	sourceMissing := false
	for _, s := range srcs {
		sm, _ := s.(map[string]any)
		id := asString(sm["id"])
		pathVal, _ := sm["path"].(string)
		declaredDigest := asString(sm["digest"])
		pr.Sources = append(pr.Sources, SourceIdentity{ID: id, Declared: declaredDigest, Computed: nil})
		last := len(pr.Sources) - 1

		if pathVal == "" {
			// no path: unavailable
			pr.Sources[last].Computed = nil
			sourceMissing = true
			continue
		}
		// limits
		if pr.LimitExceeded {
			// already stopped
			pr.Sources[last].Computed = nil
			continue
		}
		full, safeErr := safeJoin(root, pathVal)
		if safeErr != nil {
			addDiag(pr, "pap.package.path-escape", "error", "package", pathVal)
			pr.IntegrityPackage = "FAIL"
			pr.IntegrityArtifacts = "FAIL"
			sourceMissing = true
			continue
		}
		fi, err := os.Lstat(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", pathVal)
			pr.IntegrityPackage = "FAIL"
			sourceMissing = true
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			addDiag(pr, "pap.package.symlink", "error", "package", pathVal)
			pr.IntegrityPackage = "FAIL"
			sourceMissing = true
			continue
		}
		if !fi.Mode().IsRegular() {
			addDiag(pr, "pap.package.non-regular", "error", "package", pathVal)
			pr.IntegrityPackage = "FAIL"
			sourceMissing = true
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", pathVal)
			pr.IntegrityPackage = "FAIL"
			sourceMissing = true
			continue
		}
		if int64(len(data)) > fileByteLimit || pr.TotalPayloadBytes+int64(len(data)) > totalPayloadLimit {
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", pathVal)
			pr.CoverageFull = false
			pr.SourcesIntegrity = "NOT_EVALUATED"
			pr.Sources[last].Computed = nil
			// stop reading rest sources/inputs/claims
			// mark remaining sources null
			for i := last + 1; i < len(srcs); i++ {
				sm2, _ := srcs[i].(map[string]any)
				pr.Sources = append(pr.Sources, SourceIdentity{ID: asString(sm2["id"]), Declared: asString(sm2["digest"]), Computed: nil})
			}
			pr.NormalizedInputDigest = nil
			return
		}
		pr.TotalPayloadBytes += int64(len(data))
		computed := DomainHash("pap.source.raw.v1", data)
		pr.Sources[last].Computed = &computed
		if computed != declaredDigest {
			sourceMismatch = true
			addDiag(pr, "pap.integrity.source-mismatch", "error", "package", pathVal)
		}
	}
	if len(srcs) == 0 {
		pr.SourcesIntegrity = "NOT_EVALUATED"
		pr.SourcesAvailability = "NOT_APPLICABLE"
	} else {
		if sourceMissing {
			pr.SourcesIntegrity = "UNAVAILABLE"
			pr.SourcesAvailability = "UNAVAILABLE"
		} else if sourceMismatch {
			pr.SourcesIntegrity = "FAIL"
			pr.SourcesAvailability = "PASS"
		} else {
			pr.SourcesIntegrity = "PASS"
			pr.SourcesAvailability = "PASS"
		}
	}

	// read inputs
	ins, _ := m["inputs"].([]any)
	var normalizedInputs [][]byte // for set digest
	inputMismatch := false
	inputMissing := false
	inputPaths := []string{}
	for _, in := range ins {
		im, _ := in.(map[string]any)
		path := asString(im["path"])
		declaredDigest := asString(im["digest"])
		normMode := asString(im["normalization"])
		if normMode == "" {
			normMode = "lf"
		}
		// limits
		if pr.LimitExceeded {
			pr.NormalizedInputDigest = nil
			return
		}
		full, safeErr := safeJoin(root, path)
		if safeErr != nil {
			addDiag(pr, "pap.package.path-escape", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			inputMissing = true
			continue
		}
		fi, err := os.Lstat(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			inputMissing = true
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			addDiag(pr, "pap.package.symlink", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			inputMissing = true
			continue
		}
		if !fi.Mode().IsRegular() {
			addDiag(pr, "pap.package.non-regular", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			inputMissing = true
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			inputMissing = true
			continue
		}
		if int64(len(data)) > fileByteLimit || pr.TotalPayloadBytes+int64(len(data)) > totalPayloadLimit {
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", path)
			pr.CoverageFull = false
			// input integrity becomes NOT_EVALUATED; package integrity unchanged
			pr.NormalizedInputDigest = nil
			// set integrity.package? limit does not fail package identity, but input integrity NOT_EVALUATED
			// We'll handle dimension later; here set a flag by leaving NormalizedInputDigest nil and mark LimitExceeded.
			return
		}
		pr.TotalPayloadBytes += int64(len(data))
		norm := NormalizeInput(data, normMode)
		// per-file digest
		frame := FrameRecord("input", [][]byte{[]byte(path), norm})
		computed := DomainHash("pap.input.file.v1", frame)
		if computed != declaredDigest {
			inputMismatch = true
			addDiag(pr, "pap.integrity.input-mismatch", "error", "package", path)
		}
		normalizedInputs = append(normalizedInputs, norm)
		inputPaths = append(inputPaths, path)
	}
	// integrity.package input integrity: if input mismatch -> FAIL (already diagnostic). If missing -> FAIL.
	if inputMissing || inputMismatch {
		if pr.IntegrityPackage != "FAIL" {
			// missing already set FAIL
		}
		if inputMismatch {
			pr.IntegrityPackage = "FAIL"
		}
	}
	// compute set digest if inputs present
	if len(ins) > 0 && !pr.LimitExceeded && !inputMissing {
		// sort by path
		type inp struct {
			path string
			data []byte
		}
		var arr []inp
		for i, p := range inputPaths {
			arr = append(arr, inp{p, normalizedInputs[i]})
		}
		// sort
		for i := 0; i < len(arr); i++ {
			for j := i + 1; j < len(arr); j++ {
				if arr[j].path < arr[i].path {
					arr[i], arr[j] = arr[j], arr[i]
				}
			}
		}
		var records [][]byte
		for _, in := range arr {
			records = append(records, FrameRecord("input", [][]byte{[]byte(in.path), in.data}))
		}
		payload := FrameConcat(records)
		sd := DomainHash("pap.input.set.v1", payload)
		pr.NormalizedInputDigest = &sd
		// compare build.normalizedInputDigest if present
		if m != nil {
			if build, ok := m["build"].(map[string]any); ok {
				if expected, ok := build["normalizedInputDigest"].(string); ok {
					if expected != sd {
						addDiag(pr, "pap.integrity.input-mismatch", "error", "package", "build.normalizedInputDigest")
						pr.IntegrityPackage = "FAIL"
					}
				}
			}
		}
	} else if len(ins) == 0 {
		pr.NormalizedInputDigest = nil
	} else {
		// limit/missing: not computed
		pr.NormalizedInputDigest = nil
	}
	pr.InputsPresent = len(ins) > 0

	// read claims
	claims, _ := m["claims"].(map[string]any)
	// map kind to path
	claimPaths := map[string]string{}
	for kind, ref := range claims {
		rm, _ := ref.(map[string]any)
		claimPaths[kind] = asString(rm["path"])
	}
	for kind, path := range claimPaths {
		// read file
		full, safeErr := safeJoin(root, path)
		if safeErr != nil {
			addDiag(pr, "pap.package.path-escape", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			continue
		}
		fi, err := os.Lstat(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			addDiag(pr, "pap.package.symlink", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			continue
		}
		if !fi.Mode().IsRegular() {
			addDiag(pr, "pap.package.non-regular", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			addDiag(pr, "pap.package.declared-file-missing", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
			continue
		}
		if int64(len(data)) > fileByteLimit || pr.TotalPayloadBytes+int64(len(data)) > totalPayloadLimit {
			pr.LimitExceeded = true
			addDiag(pr, "pap.package.limit-exceeded", "error", "package", path)
			pr.CoverageFull = false
			continue
		}
		pr.TotalPayloadBytes += int64(len(data))
		// verify declared digest
		declaredDigest := ""
		if ref, ok := claims[kind].(map[string]any); ok {
			declaredDigest = asString(ref["digest"])
		}
		computed := DomainHash("pap.claims.v1", data)
		if computed != declaredDigest {
			addDiag(pr, "pap.integrity.claim-mismatch", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
		}
		// strict parse claim JSON? We'll parse to ensure valid; if invalid -> claim-invalid
		_, err = parseStrictJSON(data, jsonNestingLimit, jsonStringLimit)
		if err != nil {
			addDiag(pr, "pap.package.claim-invalid", "error", "package", path)
			pr.IntegrityPackage = "FAIL"
		}
		pr.ClaimBytes[kind] = data
	}
	// producer report presence
	if _, ok := claims["producerReport"]; ok {
		pr.HasProducerReport = true
	}

	// integrity.package final: if still FAIL due to mismatches, keep; if no failures and schema valid, PASS
	if pr.IntegrityPackage != "FAIL" && pr.SchemaValid {
		// but if limit exceeded? limit doesn't fail package unless manifest. So keep
		pr.IntegrityPackage = "PASS"
	}
	// if limit exceeded affecting package? no.

	// extension closure digest = declared profile closure if present
	pr.ExtensionClosureDigest = pr.ProfileClosureDigest

	// check empty check specs: required checks
	hasRequired := false
	for _, cs := range pr.CheckSpecs {
		if cs.Required {
			hasRequired = true
		}
	}
	if !hasRequired {
		// empty required set (policy absent) -> diagnostic empty-check-specs
		addDiag(pr, "pap.package.empty-check-specs", "warning", "package", "no required checks")
	}
}

func safeJoin(root, rel string) (string, error) {
	// validate path grammar already; ensure no symlink components
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("absolute")
	}
	full := filepath.Join(root, clean)
	// ensure within root using EvalSymlinks? We need reject symlinks. Check each component.
	// Walk components
	cur := root
	for _, seg := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if err != nil {
			// missing handled by caller; but for safety allow (will fail read)
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink")
		}
	}
	// containment check
	rel2, err := filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(rel2, "..") {
		return "", fmt.Errorf("escape")
	}
	// check final regular? caller checks
	_ = os.Lstat
	return full, nil
}

func checkFileLimits(pr *PackageRead, path string) error {
	// placeholder: no per-file count beyond total
	return nil
}

// regexp import
func init() {}

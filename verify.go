package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type VerifyResult struct {
	Report map[string]any
	Exit   int
	Err    error
}

var ErrNotFound = fmt.Errorf("not found")
var ErrNotDir = fmt.Errorf("not dir")
var ErrUsage = fmt.Errorf("usage")
var ErrPolicyInvalid = fmt.Errorf("policy invalid")

func resolvePackageRoot(arg string) (string, error) {
	fi, err := os.Lstat(arg)
	if err != nil {
		return "", ErrNotFound
	}
	path := arg
	if fi.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(arg)
		if err != nil {
			return "", ErrNotFound
		}
		path = resolved
	}
	fi2, err := os.Stat(path)
	if err != nil {
		return "", ErrNotFound
	}
	if !fi2.IsDir() {
		return "", ErrNotDir
	}
	abs, _ := filepath.Abs(path)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", ErrNotFound
	}
	return resolved, nil
}

func parseNow(s string) (time.Time, string, error) {
	if s == "" {
		t := time.Now().UTC()
		return t, formatNow(t), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, "", ErrUsage
	}
	// reject leap seconds? Go parse may accept :60? likely not. 
	// normalize to UTC
	t = t.UTC()
	return t, formatNow(t), nil
}

func formatNow(t time.Time) string {
	// preserve fraction, strip trailing zeros
	s := t.Format("2006-01-02T15:04:05.999999999Z07:00")
	// Actually ensure UTC Z
	s = t.UTC().Format(time.RFC3339Nano)
	return s
}

func RunVerification(pkgArg, policyArg, nowArg string, limits Limits) (map[string]any, int, error) {
	root, err := resolvePackageRoot(pkgArg)
	if err != nil {
		if err == ErrNotDir {
			return nil, 64, ErrUsage
		}
		return nil, 74, ErrNotFound
	}

	now, nowStr, err := parseNow(nowArg)
	if err != nil {
		return nil, 64, ErrUsage
	}

	// policy
	policyID := any(nil)
	policyDigest := any(nil)
	policyState := "ABSENT"
	policyPath := any(nil)
	if policyArg != "" {
		pb, err := os.ReadFile(policyArg)
		if err != nil {
			return nil, 64, ErrPolicyInvalid
		}
		pval, err := parseStrictJSON(pb, limits)
		if err != nil {
			return nil, 64, ErrPolicyInvalid
		}
		pcanon, err := canonicalJSON(pval)
		if err != nil {
			return nil, 64, ErrPolicyInvalid
		}
		if err := validateTrustPolicy(pval); err != nil {
			return nil, 64, ErrPolicyInvalid
		}
		policyDigest = H("pap.trust-policy.v1", pcanon)
		pm, _ := pval.(map[string]any)
		if pm != nil {
			if id, ok := pm["id"].(string); ok {
				policyID = id
			}
		}
		policyPath = policyArg
		// state
		policyState = evaluatePolicyState(pm, now)
		if policyState == "INVALID" {
			return nil, 64, ErrPolicyInvalid
		}
	}

	// read manifest
	manifestPath := filepath.Join(root, "assurance-package.json")
	manifestBytes, merr := os.ReadFile(manifestPath)
	manifestMissing := merr != nil
	manifestLimitExceeded := false
	if !manifestMissing && len(manifestBytes) > limits.ManifestBytes {
		manifestLimitExceeded = true
	}

	var manifestVal any
	var manifestParseErr error
	var manifestParsed bool
	if !manifestMissing && !manifestLimitExceeded {
		v, err := parseStrictJSON(manifestBytes, limits)
		if err != nil {
			manifestParseErr = err
		} else {
			manifestVal = v
			manifestParsed = true
		}
	}

	// canonical manifest bytes
	var packageIdentity any
	var jcsErr error
	if manifestParsed {
		canon, err := canonicalJSON(manifestVal)
		if err != nil {
			jcsErr = err
		} else {
			packageIdentity = H("pap.package.v1", canon)
		}
	}
	// parse failure if manifest missing/read error/limit/parse/jcs
	parseFailure := manifestMissing || manifestLimitExceeded || manifestParseErr != nil || jcsErr != nil

	// validate manifest
	var diags []Diagnostic
	manifestValid := false
	if manifestParsed && jcsErr == nil {
		d, ok := validateManifest(manifestVal, limits)
		diags = append(diags, d...)
		manifestValid = ok
	}
	// if parse failure, add diagnostic
	if manifestMissing {
		diags = append(diags, Diagnostic{Code: "pap.package.io", Severity: "error", Scope: "package", Message: "manifest missing or unreadable"})
	} else if merr != nil {
		diags = append(diags, Diagnostic{Code: "pap.package.io", Severity: "error", Scope: "package", Message: "manifest read error"})
	}
	if manifestLimitExceeded {
		diags = append(diags, Diagnostic{Code: "pap.package.limit-exceeded", Severity: "error", Scope: "manifest", Message: "manifest byte limit exceeded"})
	}
	if manifestParseErr != nil {
		code := "pap.package.manifest-json"
		msg := manifestParseErr.Error()
		if strings.Contains(msg, "duplicate key") {
			code = "pap.package.duplicate-key"
		}
		diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "manifest", Message: msg})
	}
	if jcsErr != nil {
		diags = append(diags, Diagnostic{Code: "pap.package.manifest-json", Severity: "error", Scope: "manifest", Message: jcsErr.Error()})
	}

	// papVersion for report
	var papVersion any
	if manifestParsed {
		if mv, ok := manifestVal.(map[string]any); ok {
			papVersion = mv["papVersion"]
		}
	}
	if parseFailure {
		papVersion = nil
	}

	// declared checks
	type checkSpec struct {
		ID       string
		Version  string
		Required bool
	}
	var checkSpecs []checkSpec
	if manifestParsed {
		if mv, ok := manifestVal.(map[string]any); ok {
			if arr, ok2 := mv["checkSpecs"].([]any); ok2 {
				for _, c := range arr {
					cm, _ := c.(map[string]any)
					if cm == nil {
						continue
					}
					id, _ := cm["id"].(string)
					ver, _ := cm["version"].(string)
					req := true
					if r, ok3 := cm["required"].(bool); ok3 {
						req = r
					}
					checkSpecs = append(checkSpecs, checkSpec{ID: id, Version: ver, Required: req})
				}
			}
		}
	}

	// integrity.package status
	integrityPackage := "FAIL"
	if parseFailure {
		integrityPackage = "FAIL"
	} else if !manifestValid {
		integrityPackage = "FAIL"
	} else {
		integrityPackage = "PASS"
	}
	// limit reading inputs may set NOT_EVALUATED later

	// Read declared files
	// Build list of declared payload entries in fixed order:
	// artifacts, sources (embedded), inputs, claims
	mv, _ := manifestVal.(map[string]any)
	var artifacts []map[string]any
	var sources []map[string]any
	var inputs []map[string]any
	claimsMap := map[string]map[string]any{}
	if mv != nil {
		if arr, ok := mv["artifacts"].([]any); ok {
			for _, a := range arr {
				am, _ := a.(map[string]any)
				if am != nil {
					artifacts = append(artifacts, am)
				}
			}
		}
		if arr, ok := mv["sources"].([]any); ok {
			for _, s := range arr {
				sm, _ := s.(map[string]any)
				if sm != nil {
					sources = append(sources, sm)
				}
			}
		}
		if arr, ok := mv["inputs"].([]any); ok {
			for _, in := range arr {
				im, _ := in.(map[string]any)
				if im != nil {
					inputs = append(inputs, im)
				}
			}
		}
		if cm, ok := mv["claims"].(map[string]any); ok {
			for k, v := range cm {
				vm, _ := v.(map[string]any)
				if vm != nil {
					claimsMap[k] = vm
				}
			}
		}
	}

	// identities arrays
	artifactIdentities := []map[string]any{}
	sourceIdentities := []map[string]any{}
	// We'll compute normalized input digest from read inputs.

	// Track read status and computed digests
	artifactComputed := map[string]any{} // id -> digest or nil
	sourceComputed := map[string]any{}
	inputComputed := map[string]any{} // id -> digest or nil

	// limit tracking
	limitExceeded := false
	scanCompleted := true
	totalBytes := 0

	// helper to read a declared file safely
	readDeclaredFile := func(rel string) ([]byte, error, string) {
		// returns bytes, err, code
		if !validPathGrammar(rel, limits) {
			return nil, fmt.Errorf("invalid path"), "pap.package.path-invalid"
		}
		// clean and confine
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) {
			return nil, fmt.Errorf("abs"), "pap.package.path-invalid"
		}
		full := filepath.Join(root, clean)
		rel2, err := filepath.Rel(root, full)
		if err != nil || strings.HasPrefix(rel2, "..") {
			return nil, fmt.Errorf("escape"), "pap.package.path-escape"
		}
		fi, err := os.Lstat(full)
		if err != nil {
			return nil, err, "pap.package.declared-file-missing"
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink"), "pap.package.symlink"
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("nonregular"), "pap.package.non-regular"
		}
		if fi.Size() > int64(limits.FileBytes) {
			return nil, fmt.Errorf("file too large"), "pap.package.limit-exceeded"
		}
		// total bytes checked by caller
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, err, "pap.package.io"
		}
		return b, nil, ""
	}

	// If manifest invalid/parse failure, we still might not read payloads. RFC: if manifest fails schema, payloads not read, integrity.artifacts NOT_EVALUATED.
	readPayloads := manifestValid && !parseFailure

	// Fixed order: artifacts, sources, inputs, claims
	// Artifacts
	artifactMismatch := false
	artifactMissing := false
	if readPayloads {
		for _, a := range artifacts {
			id, _ := a["id"].(string)
			path, _ := a["path"].(string)
			declaredDigest, _ := a["digest"].(string)
			declaredBytes, _ := a["bytes"].(int64)
			// count limit
			// read
			if limitExceeded {
				// skip all remaining, computed null
				artifactComputed[id] = nil
				artifactIdentities = append(artifactIdentities, map[string]any{
					"id": id, "declared": declaredDigest, "computed": nil,
				})
				continue
			}
			b, err, code := readDeclaredFile(path)
			if err != nil {
				if code == "pap.package.limit-exceeded" {
					limitExceeded = true
				}
				// missing/nonregular etc.
				if code == "pap.package.declared-file-missing" || code == "pap.package.symlink" || code == "pap.package.non-regular" || code == "pap.package.io" {
					artifactMissing = true
					diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: code})
				} else if code == "pap.package.limit-exceeded" {
					limitExceeded = true
					diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: "limit exceeded"})
				} else {
					diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: code})
				}
				artifactComputed[id] = nil
				artifactIdentities = append(artifactIdentities, map[string]any{
					"id": id, "declared": declaredDigest, "computed": nil,
				})
				// integrity.artifacts FAIL for missing/mismatch
				artifactMismatch = true
				continue
			}
			// total bytes
			if totalBytes+len(b) > limits.TotalPayloadBytes {
				limitExceeded = true
				diags = append(diags, Diagnostic{Code: "pap.package.limit-exceeded", Severity: "error", Scope: "package", Message: "total bytes"})
				artifactComputed[id] = nil
				artifactIdentities = append(artifactIdentities, map[string]any{
					"id": id, "declared": declaredDigest, "computed": nil,
				})
				artifactMismatch = true
				continue
			}
			totalBytes += len(b)
			computed := H("pap.artifact.v1", b)
			artifactComputed[id] = computed
			artifactIdentities = append(artifactIdentities, map[string]any{
				"id": id, "declared": declaredDigest, "computed": computed,
			})
			if computed != declaredDigest || int64(len(b)) != declaredBytes {
				artifactMismatch = true
				diags = append(diags, Diagnostic{Code: "pap.integrity.artifact-mismatch", Severity: "error", Scope: "package", Message: "artifact mismatch"})
			}
		}
	}

	// Sources
	sourceMismatch := false
	sourceMissing := false
	embeddedSourceCount := 0
	for _, s := range sources {
		id, _ := s["id"].(string)
		declaredDigest, _ := s["digest"].(string)
		path, _ := s["path"].(string)
		if path == "" {
			// referenced-only: no computed
			sourceComputed[id] = nil
			sourceIdentities = append(sourceIdentities, map[string]any{
				"id": id, "declared": declaredDigest, "computed": nil,
			})
			continue
		}
		if limitExceeded {
			sourceComputed[id] = nil
			sourceIdentities = append(sourceIdentities, map[string]any{
				"id": id, "declared": declaredDigest, "computed": nil,
			})
			continue
		}
		b, err, code := readDeclaredFile(path)
		if err != nil {
			if code == "pap.package.limit-exceeded" {
				limitExceeded = true
			}
			if code != "pap.package.limit-exceeded" {
				sourceMissing = true
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: code})
			} else {
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: "limit exceeded"})
			}
			sourceComputed[id] = nil
			sourceIdentities = append(sourceIdentities, map[string]any{
				"id": id, "declared": declaredDigest, "computed": nil,
			})
			sourceMismatch = true
			continue
		}
		if totalBytes+len(b) > limits.TotalPayloadBytes {
			limitExceeded = true
			diags = append(diags, Diagnostic{Code: "pap.package.limit-exceeded", Severity: "error", Scope: "package", Message: "total bytes"})
			sourceComputed[id] = nil
			sourceIdentities = append(sourceIdentities, map[string]any{
				"id": id, "declared": declaredDigest, "computed": nil,
			})
			sourceMismatch = true
			continue
		}
		totalBytes += len(b)
		computed := H("pap.source.raw.v1", b)
		sourceComputed[id] = computed
		sourceIdentities = append(sourceIdentities, map[string]any{
			"id": id, "declared": declaredDigest, "computed": computed,
		})
		if computed != declaredDigest {
			sourceMismatch = true
			diags = append(diags, Diagnostic{Code: "pap.integrity.source-mismatch", Severity: "error", Scope: "package", Message: "source mismatch"})
		}
		embeddedSourceCount++
	}

	// Inputs
	inputMismatch := false
	inputMissing := false
	inputsReadAll := true
	var normalizedInputBytesList [][]byte
	var normalizedInputPaths []string
	for _, in := range inputs {
		id, _ := in["id"].(string)
		path, _ := in["path"].(string)
		declaredDigest, _ := in["digest"].(string)
		norm, _ := in["normalization"].(string)
		if limitExceeded {
			inputComputed[id] = nil
			inputsReadAll = false
			continue
		}
		b, err, code := readDeclaredFile(path)
		if err != nil {
			if code == "pap.package.limit-exceeded" {
				limitExceeded = true
			}
			if code != "pap.package.limit-exceeded" {
				inputMissing = true
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: code})
			} else {
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: "limit exceeded"})
			}
			inputComputed[id] = nil
			inputsReadAll = false
			inputMismatch = true
			continue
		}
		if totalBytes+len(b) > limits.TotalPayloadBytes {
			limitExceeded = true
			diags = append(diags, Diagnostic{Code: "pap.package.limit-exceeded", Severity: "error", Scope: "package", Message: "total bytes"})
			inputComputed[id] = nil
			inputsReadAll = false
			inputMismatch = true
			continue
		}
		totalBytes += len(b)
		// per-file digest
		normalized := normalizeInputBytes(b, norm)
		normalizedInputBytesList = append(normalizedInputBytesList, normalized)
		normalizedInputPaths = append(normalizedInputPaths, path)
		perFileDigest := H("pap.input.file.v1", frameRecord("input", [][]byte{[]byte(path), normalized}))
		inputComputed[id] = perFileDigest
		if perFileDigest != declaredDigest {
			inputMismatch = true
			diags = append(diags, Diagnostic{Code: "pap.integrity.input-mismatch", Severity: "error", Scope: "package", Message: "input mismatch"})
		}
		}

	// compute normalized input digest
	var normalizedInputDigest any
	if len(inputs) == 0 {
		normalizedInputDigest = nil
	} else if limitExceeded || !inputsReadAll {
		normalizedInputDigest = nil
	} else {
		// sort by path
		type pair struct {
			path string
			nb   []byte
		}
		var pairs []pair
		for i, in := range inputs {
			p, _ := in["path"].(string)
			pairs = append(pairs, pair{path: p, nb: normalizedInputBytesList[i]})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].path < pairs[j].path })
		var payload []byte
		for _, pr := range pairs {
			payload = append(payload, frameRecord("input", [][]byte{[]byte(pr.path), pr.nb})...)
		}
		normalizedInputDigest = H("pap.input.set.v1", payload)
	}
	// verify against build.normalizedInputDigest if declared
	if mv != nil {
		if build, ok := mv["build"].(map[string]any); ok {
			if declared, ok2 := build["normalizedInputDigest"].(string); ok2 {
				if normalizedInputDigest != nil && normalizedInputDigest.(string) != declared {
					inputMismatch = true
					diags = append(diags, Diagnostic{Code: "pap.integrity.input-mismatch", Severity: "error", Scope: "package", Message: "normalized input mismatch"})
				}
			}
		}
	}

	// claim digests for identities? identities.claims not top-level separate; claims digests in check subject maybe. identities has no claims array. Fine.

	// Claims
	claimMismatch := false
	claimMissing := false
	claimKinds := make([]string, 0, len(claimsMap))
	for k := range claimsMap {
		claimKinds = append(claimKinds, k)
	}
	sort.Strings(claimKinds)
	for _, kind := range claimKinds {
		cm := claimsMap[kind]
		path, _ := cm["path"].(string)
		declaredDigest, _ := cm["digest"].(string)
		if limitExceeded {
			claimMissing = true
			continue
		}
		b, err, code := readDeclaredFile(path)
		if err != nil {
			if code == "pap.package.limit-exceeded" {
				limitExceeded = true
			}
			if code != "pap.package.limit-exceeded" {
				claimMissing = true
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: code})
			} else {
				diags = append(diags, Diagnostic{Code: code, Severity: "error", Scope: "package", Message: "limit exceeded"})
			}
			claimMismatch = true
			continue
		}
		if totalBytes+len(b) > limits.TotalPayloadBytes {
			limitExceeded = true
			diags = append(diags, Diagnostic{Code: "pap.package.limit-exceeded", Severity: "error", Scope: "package", Message: "total bytes"})
			claimMismatch = true
			continue
		}
		totalBytes += len(b)
		computed := H("pap.claims.v1", b)
		if computed != declaredDigest {
			claimMismatch = true
			diags = append(diags, Diagnostic{Code: "pap.integrity.claim-mismatch", Severity: "error", Scope: "package", Message: "claim mismatch"})
		}
	}

	// undeclared file scan
	undeclaredDiags, scanCompleted2 := scanUndeclared(root, mv, limits)
	diags = append(diags, undeclaredDiags...)
	if !scanCompleted2 {
		scanCompleted = false
	}

	// integrity.artifacts status
	pathOrFileIssue := false
	for _, d := range diags {
		if d.Code == "pap.package.path-invalid" || d.Code == "pap.package.path-duplicate" ||
			d.Code == "pap.package.symlink" || d.Code == "pap.package.non-regular" ||
			d.Code == "pap.package.declared-file-missing" || d.Code == "pap.package.path-escape" {
			pathOrFileIssue = true
		}
	}
	integrityArtifacts := "NOT_EVALUATED"
	if parseFailure {
		integrityArtifacts = "NOT_EVALUATED"
	} else if !manifestValid {
		if pathOrFileIssue {
			integrityArtifacts = "FAIL"
		} else {
			integrityArtifacts = "NOT_EVALUATED"
		}
	} else if readPayloads {
		if limitExceeded {
			integrityArtifacts = "NOT_EVALUATED"
		} else if artifactMissing || artifactMismatch {
			integrityArtifacts = "FAIL"
		} else {
			integrityArtifacts = "PASS"
		}
	}

	// sources.integrity status
	sourcesIntegrity := "NOT_EVALUATED"
	sourcesAvailability := "NOT_APPLICABLE"
	if parseFailure || !manifestValid {
		sourcesIntegrity = "NOT_EVALUATED"
	} else {
		// if no sources
		if len(sources) == 0 {
			sourcesIntegrity = "NOT_EVALUATED"
		} else {
			// referenced-only handling
			hasReferenced := false
			for _, s := range sources {
				if p, _ := s["path"].(string); p == "" {
					hasReferenced = true
				}
			}
			if sourceMissing || sourceMismatch {
				if limitExceeded {
					sourcesIntegrity = "NOT_EVALUATED"
				} else {
					sourcesIntegrity = "FAIL"
				}
			} else if hasReferenced {
				sourcesIntegrity = "UNAVAILABLE"
			} else {
				sourcesIntegrity = "PASS"
			}
		}
		// availability
		// determine if any required check is source-dependent
		sourceDependentRequired := false
		for _, cs := range checkSpecs {
			if cs.Required && cs.ID == "pap.check.source-quote/1" {
				sourceDependentRequired = true
			}
		}
		if sourceDependentRequired {
			// check if all sources used have snapshots
			unavail := false
			for _, s := range sources {
				if p, _ := s["path"].(string); p == "" {
					unavail = true
				}
			}
			if unavail {
				sourcesAvailability = "UNAVAILABLE"
			} else {
				sourcesAvailability = "PASS"
			}
		} else {
			sourcesAvailability = "NOT_APPLICABLE"
		}
	}
	if limitExceeded && len(sources) > 0 {
		sourcesIntegrity = "NOT_EVALUATED"
	}

	// if manifest invalid, sources integrity NOT_EVALUATED already.

	// integrity.package adjust for limit-exceeded on inputs? RFC: input limit -> integrity.package NOT_EVALUATED.
	if integrityPackage == "PASS" && limitExceeded {
		// if input limit exceeded, integrity.package NOT_EVALUATED
		// detect if inputs affected: if limitExceeded and len(inputs)>0
		if len(inputs) > 0 {
			integrityPackage = "NOT_EVALUATED"
		}
	}
	// if claim missing/mismatch, integrity.package FAIL
	if claimMissing || claimMismatch {
		integrityPackage = "FAIL"
	}
	if inputMissing || inputMismatch {
		// input digest mismatch fails integrity.package
		if inputMismatch {
			integrityPackage = "FAIL"
		}
		// missing input declared file fails too
		if inputMissing {
			integrityPackage = "FAIL"
		}
	}
	if artifactMissing || artifactMismatch {
		// missing artifact fails integrity.artifacts, but integrity.package? RFC says every declared file exists => package FAIL. We'll set package FAIL for missing/nonregular; mismatch of digest is artifact-level not package? 
		// cases expect integrity.package FAIL for missing artifact. For digest mismatch (F02) identityOnly ignores verdict/dimensions maybe. Set package FAIL only for missing/nonregular/path issues, not digest mismatch.
		if artifactMissing {
			integrityPackage = "FAIL"
		}
	}
	if sourceMissing {
		integrityPackage = "FAIL"
	}
	// manifest valid but limit on manifest already FAIL.

	// If manifest parse failure, integrity.package FAIL
	if parseFailure || !manifestValid {
		integrityPackage = "FAIL"
	}

	// compatibility unsupported flag
	unsupportedVersion := false
	if manifestParsed {
		if mv2, ok := manifestVal.(map[string]any); ok {
			pv, _ := mv2["papVersion"].(string)
			if pv != "0.1" {
				unsupportedVersion = true
			}
		}
	}

	// critical extension / feature flags
	criticalExtUnsupported := false
	featureUnsupported := false
	optionalExtIgnored := false
	if manifestParsed {
		if mv2, ok := manifestVal.(map[string]any); ok {
			if ext, ok2 := mv2["extensions"].(map[string]any); ok2 {
				for _, v := range ext {
					vm, _ := v.(map[string]any)
					if vm == nil {
						continue
					}
					if crit, _ := vm["critical"].(bool); crit {
						criticalExtUnsupported = true
					} else {
						optionalExtIgnored = true
					}
				}
			}
			if rf, ok2 := mv2["requiredFeatures"].([]any); ok2 && len(rf) > 0 {
				featureUnsupported = true
			}
		}
	}
	// add limitations for ignored extensions
	if optionalExtIgnored {
		diags = append(diags, Diagnostic{Code: "pap.extension.ignored", Severity: "info", Scope: "extensions", Message: "ignored"})
	}

	// unknown check detection
	for _, cs := range checkSpecs {
		// registry empty => all checks unsupported
		_ = cs
	}
	// Actually all declared checks are unsupported in Phase 2a. But if schema invalid, checks NOT_EVALUATED not unsupported.

	// required checks list
	var requiredChecks []string
	for _, cs := range checkSpecs {
		if cs.Required {
			requiredChecks = append(requiredChecks, cs.ID)
		}
	}

	// required dimensions
	reqDimsSet := map[string]bool{}
	implied := func(checkID string) []string {
		switch checkID {
		case "pap.check.digest-integrity/1":
			return []string{"integrity", "checks"}
		case "pap.check.source-quote/1":
			return []string{"sources", "checks"}
		case "pap.check.relation-consistency/1":
			return []string{"checks"}
		default:
			return []string{"checks"}
		}
	}
	for _, rc := range requiredChecks {
		for _, d := range implied(rc) {
			reqDimsSet[d] = true
		}
	}
	// sort by enumerable order
	dimOrder := []string{"integrity", "sources", "signature", "trust", "checks", "humanReview"}
	var requiredDimensions []string
	for _, d := range dimOrder {
		if reqDimsSet[d] {
			requiredDimensions = append(requiredDimensions, d)
		}
	}
	if requiredDimensions == nil {
		requiredDimensions = []string{}
	}
	if requiredChecks == nil {
		requiredChecks = []string{}
	}

	// checks dimension results
	checkResults := []map[string]any{}
	for _, cs := range checkSpecs {
		outcome := "NOT_EVALUATED"
		if manifestValid && !parseFailure {
			outcome = "UNSUPPORTED"
		}
		checkResults = append(checkResults, map[string]any{
			"checkId":  cs.ID,
			"outcome":  outcome,
			"required": cs.Required,
		})
	}
	if checkResults == nil {
		checkResults = []map[string]any{}
	}

	// top-level checks[] empty (unsupported has no record)

	// coverage
	checksEvaluated := 0
	checksPassed := 0
	checksFailed := 0
	checksUnsupported := 0
	checksNotEvaluated := 0
	for _, cs := range checkSpecs {
		if !cs.Required {
			continue
		}
		outcome := "NOT_EVALUATED"
		if manifestValid && !parseFailure {
			outcome = "UNSUPPORTED"
		}
		switch outcome {
		case "PASS":
			checksPassed++
			checksEvaluated++
		case "FAIL":
			checksFailed++
			checksEvaluated++
		case "UNSUPPORTED":
			checksUnsupported++
		case "NOT_EVALUATED":
			checksNotEvaluated++
		}
	}

	// dimensionsEvaluated
	// decided logic for root integrity: both package and artifacts decided
	integrityDecided := isDecidedStatus(integrityPackage) && isDecidedStatus(integrityArtifacts)
	sourcesDecided := isDecidedStatus(sourcesIntegrity) && isDecidedStatus(sourcesAvailability)
	checksDecided := true
	if len(requiredChecks) > 0 {
		// decided only if every required check PASS or FAIL
		checksDecided = false
		allPassFail := true
		for _, cs := range checkSpecs {
			if !cs.Required {
				continue
			}
			outcome := "NOT_EVALUATED"
			if manifestValid && !parseFailure {
				outcome = "UNSUPPORTED"
			}
			if outcome != "PASS" && outcome != "FAIL" {
				allPassFail = false
			}
		}
		if allPassFail && len(requiredChecks) > 0 {
			checksDecided = true
		}
	} else {
		// no required checks: checks dimension decided? empty set considered decided? We'll say true if no required checks
		checksDecided = true
	}
	if len(requiredChecks) == 0 {
		checksDecided = false // empty required set not decided? coverage full false anyway
	}

	dimensionsEvaluated := 0
	for _, d := range requiredDimensions {
		decided := false
		switch d {
		case "integrity":
			decided = integrityDecided
		case "sources":
			decided = sourcesDecided
		case "checks":
			decided = checksDecided
		case "signature", "trust", "humanReview":
			decided = false
		}
		if decided {
			dimensionsEvaluated++
		}
	}

	scanCompletedFinal := scanCompleted
	if limitExceeded {
		// scan may still complete; keep scanCompleted
	}

	full := true
	if len(requiredChecks) == 0 && len(requiredDimensions) == 0 {
		full = false
	}
	if checksNotEvaluated != 0 || checksUnsupported != 0 {
		full = false
	}
	if dimensionsEvaluated != len(requiredDimensions) {
		full = false
	}
	if !scanCompletedFinal {
		full = false
	}
	if limitExceeded {
		full = false
	}
	if len(requiredChecks) == 0 {
		full = false
	}

	// verdict
	verdict := "PASS"
	// FAIL conditions
	failVerdict := false
	if integrityPackage == "FAIL" || integrityArtifacts == "FAIL" {
		failVerdict = true
	}
	if sourcesIntegrity == "FAIL" {
		failVerdict = true
	}
	if claimMismatch || claimMissing || inputMismatch || inputMissing || artifactMissing || sourceMissing || artifactMismatch || sourceMismatch {
		// claim mismatch already integrity package fail
	}
	// any required check FAIL?
	for _, cr := range checkResults {
		if cr["required"].(bool) && cr["outcome"] == "FAIL" {
			failVerdict = true
		}
	}
	if failVerdict {
		verdict = "FAIL"
	} else {
		// UNTRUSTED: none (no trust policy evaluation) 
		// UNSUPPORTED
		unsupportedVerdict := false
		if checksUnsupported > 0 {
			unsupportedVerdict = true
		}
		if criticalExtUnsupported || featureUnsupported || unsupportedVersion {
			unsupportedVerdict = true
		}
		if unsupportedVerdict {
			verdict = "UNSUPPORTED"
		} else {
			// INCOMPLETE
			incomplete := false
			for _, d := range requiredDimensions {
				var st string
				switch d {
				case "integrity":
					if !integrityDecided {
						incomplete = true
					}
					_ = st
				case "sources":
					if sourcesIntegrity == "NOT_EVALUATED" || sourcesIntegrity == "UNAVAILABLE" || sourcesIntegrity == "UNKNOWN" {
						incomplete = true
					}
					if sourcesAvailability == "UNAVAILABLE" {
						incomplete = true
					}
				case "checks":
					if checksNotEvaluated > 0 {
						incomplete = true
					}
				}
			}
			if checksNotEvaluated > 0 {
				incomplete = true
			}
			if limitExceeded {
				incomplete = true
			}
			if !scanCompletedFinal {
				incomplete = true
			}
			if !full {
				// full false can be due unsupported; but if no unsupported, incomplete
				if checksUnsupported == 0 && !criticalExtUnsupported && !featureUnsupported && !unsupportedVersion {
					incomplete = true
				}
			}
			if len(requiredChecks) == 0 {
				incomplete = true
				diags = append(diags, Diagnostic{Code: "pap.package.empty-check-specs", Severity: "warning", Scope: "package", Message: "empty required set"})
			}
			if policyState == "STALE" {
				incomplete = true
			}
			if incomplete {
				verdict = "INCOMPLETE"
			} else {
				// PASS requires all positive; if no required checks? already incomplete
				verdict = "PASS"
			}
		}
	}

	// If parse failure, verdict FAIL already? failVerdict true due integrity package FAIL, so FAIL.

	// diagnostics for unsupported checks
	if manifestValid && !parseFailure && len(checkSpecs) > 0 {
		diags = append(diags, Diagnostic{Code: "pap.check.unsupported", Severity: "warning", Scope: "checks", Message: "checks not implemented in Phase 2a"})
	}
	// diagnostic for empty check specs
	if len(requiredChecks) == 0 && manifestValid && !parseFailure {
		// already added
	}
	// compat diagnostics already added by validateManifest

	sortDiagnostics(diags)

	// limitations
	limitations := []map[string]any{}
	addLimitation := func(code, detail string) {
		limitations = append(limitations, map[string]any{"code": code, "detail": detail})
	}
	if !scanCompletedFinal {
		addLimitation("pap.package.undeclared-scan-incomplete", "scan incomplete")
	}
	if limitExceeded {
		addLimitation("pap.package.limit-exceeded", "limit exceeded")
	}
	if optionalExtIgnored {
		addLimitation("pap.extension.ignored", "ignored extension")
	}
	// non-positive statuses
	if integrityPackage == "NOT_EVALUATED" {
		addLimitation("pap.package.limit-exceeded", "package not evaluated")
	}
	if sourcesIntegrity == "UNAVAILABLE" {
		addLimitation("pap.source.unavailable", "source unavailable")
	}
	// checks unsupported limitation
	if checksUnsupported > 0 {
		addLimitation("pap.check.unsupported", "unsupported check")
	}
	if checksNotEvaluated > 0 {
		addLimitation("pap.check.not-evaluated", "check not evaluated")
	}
	if len(requiredChecks) == 0 {
		addLimitation("pap.package.empty-check-specs", "empty required set")
	}
	if unsupportedVersion {
		// compat diagnostic already
	}
	sortLimitations(limitations)
	if limitations == nil {
		limitations = []map[string]any{}
	}

	// diagnostic maps
	diagMaps := []map[string]any{}
	for _, d := range diags {
		diagMaps = append(diagMaps, diagMap(d))
	}
	if diagMaps == nil {
		diagMaps = []map[string]any{}
	}

	// identities artifacts/sources sort? already manifest order
	// ensure arrays not nil
	if artifactIdentities == nil {
		artifactIdentities = []map[string]any{}
	}
	if sourceIdentities == nil {
		sourceIdentities = []map[string]any{}
	}

	// checker identity
	verifierID := "pap.verifier.go"
	verifierVersion := "0.1.0"
	// compute closure from current working dir? We'll use a fixed empty closure? 
	// For report, need implementationDigest. We'll compute from git tracked files if possible.
	implDigest, checkerIdent := computeCheckerIdentitySelf()
	// If fails, use placeholder? Should not.
	_ = implDigest

	// report map
	report := map[string]any{
		"reportVersion": "0.1",
		"verifier": map[string]any{
			"id":                  verifierID,
			"version":             verifierVersion,
			"implementationDigest": implDigest,
			"checkerIdentities":    []any{checkerIdent},
		},
		"package": map[string]any{
			"identity":  packageIdentity,
			"papVersion": papVersion,
			"path":      root,
		},
		"policy": map[string]any{
			"id":     policyID,
			"digest": policyDigest,
			"state":  policyState,
			"path":   policyPath,
		},
		"evaluatedAt": nowStr,
		"identities": map[string]any{
			"packageIdentity":          packageIdentity,
			"artifacts":                artifactIdentities,
			"sources":                  sourceIdentities,
			"normalizedInputDigest":    normalizedInputDigest,
			"extensionClosureDigest":   nil,
			"checkerIdentity":          checkerIdent,
			"verificationRecordIdentity": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		"dimensions": map[string]any{
			"integrity": map[string]any{
				"package":   integrityPackage,
				"artifacts": integrityArtifacts,
			},
			"sources": map[string]any{
				"integrity":    sourcesIntegrity,
				"availability": sourcesAvailability,
			},
			"signature": map[string]any{
				"validity": "NOT_APPLICABLE",
			},
			"trust": map[string]any{
				"signerIdentity":      "NOT_APPLICABLE",
				"policyDecision":      "NOT_EVALUATED",
				"checkerRecognition":  "NOT_EVALUATED",
				"profileRecognition":  "NOT_EVALUATED",
			},
			"checks": map[string]any{
				"results": checkResults,
			},
			"humanReview": map[string]any{
				"status": "NOT_APPLICABLE",
			},
			"semanticTruth":      "NOT_EVALUATED",
			"legalEnforceability": "NOT_EVALUATED",
		},
		"checks": []any{},
		"coverage": map[string]any{
			"requiredChecks":       requiredChecks,
			"checksEvaluated":      checksEvaluated,
			"checksPassed":         checksPassed,
			"checksFailed":         checksFailed,
			"checksUnsupported":    checksUnsupported,
			"checksNotEvaluated":   checksNotEvaluated,
			"requiredDimensions":   requiredDimensions,
			"dimensionsEvaluated":   dimensionsEvaluated,
			"full":                 full,
		},
		"limitations": limitations,
		"verdict":     verdict,
		"diagnostics": diagMaps,
	}

	// profile closureDigest -> identities.extensionClosureDigest = declared profile.closureDigest
	if manifestParsed {
		if mv2, ok := manifestVal.(map[string]any); ok {
			if prof, ok2 := mv2["profile"].(map[string]any); ok2 {
				if cd, ok3 := prof["closureDigest"].(string); ok3 {
					report["identities"].(map[string]any)["extensionClosureDigest"] = cd
				}
			}
		}
	}

	// compute verificationRecordIdentity
	// Build identity form: copy report, remove excluded fields, replace verificationRecordIdentity with placeholder (already), remove producerClaims (none), package.path? excluded package.path and policy.path. diagnostics messages excluded.
	// We'll implement a function.
	vri := computeVerificationRecordIdentity(report)
	report["identities"].(map[string]any)["verificationRecordIdentity"] = vri

	// Now output evaluatedAt as nowStr already.

	return report, verdictExit(verdict), nil
}

func evaluatePolicyState(pm map[string]any, now time.Time) string {
	if pm == nil {
		return "ABSENT"
	}
	// if issuedAt/expiresAt present
	issued := ""
	expires := ""
	if v, ok := pm["issuedAt"].(string); ok {
		issued = v
	}
	if v, ok := pm["expiresAt"].(string); ok {
		expires = v
	}
	// also maybe nested? Trust policy top-level fields likely issuedAt/expiresAt
	if issued == "" && expires == "" {
		// maybe no freshness window => FRESH
		return "FRESH"
	}
	if issued != "" {
		t, err := time.Parse(time.RFC3339Nano, issued)
		if err == nil {
			if now.Before(t) {
				return "STALE" // not-yet-valid treated stale
			}
		}
	}
	if expires != "" {
		t, err := time.Parse(time.RFC3339Nano, expires)
		if err == nil {
			if now.After(t) {
				return "STALE"
			}
		}
	}
	return "FRESH"
}

func scanUndeclared(root string, manifest any, limits Limits) ([]Diagnostic, bool) {
	var diags []Diagnostic
	// declared set
	declared := map[string]bool{}
	mv, _ := manifest.(map[string]any)
	if mv != nil {
		add := func(p string) { if p != "" { declared[p] = true } }
		if arr, ok := mv["artifacts"].([]any); ok {
			for _, a := range arr {
				am, _ := a.(map[string]any)
				if am != nil {
					if p, ok := am["path"].(string); ok { add(p) }
				}
			}
		}
		if arr, ok := mv["inputs"].([]any); ok {
			for _, in := range arr {
				im, _ := in.(map[string]any)
				if im != nil {
					if p, ok := im["path"].(string); ok { add(p) }
				}
			}
		}
		if arr, ok := mv["sources"].([]any); ok {
			for _, s := range arr {
				sm, _ := s.(map[string]any)
				if sm != nil {
					if p, ok := sm["path"].(string); ok { add(p) }
				}
			}
		}
		if cm, ok := mv["claims"].(map[string]any); ok {
			for _, v := range cm {
				vm, _ := v.(map[string]any)
				if vm != nil {
					if p, ok := vm["path"].(string); ok { add(p) }
				}
			}
		}
	}
	// enumerate
	completed := true
	var walk func(dir string, prefix string) error
	walk = func(dir string, prefix string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			completed = false
			return err
		}
		for _, e := range entries {
			name := e.Name()
			rel := name
			if prefix != "" {
				rel = prefix + "/" + name
			}
			full := filepath.Join(dir, name)
			// skip manifest
			if rel == "assurance-package.json" {
				continue
			}
			// symlinks: if symlink, treat as undeclared? RFC says undeclared regular file. We'll not follow.
			info, err := e.Info()
			if err != nil {
				completed = false
				continue
			}
			if e.IsDir() {
				if err := walk(full, rel); err != nil {
					// already handled
				}
				continue
			}
			// regular file?
			if !info.Mode().IsRegular() {
				continue
			}
			// if under signatures/ and suffix .dsse.json, not undeclared? Signature envelopes not declared; skip undeclared warning? RFC: envelopes under signatures/ with suffix are read; other files undeclared. We'll treat .dsse.json as declared-ish (no warning).
			if strings.HasPrefix(rel, "signatures/") && strings.HasSuffix(rel, ".dsse.json") {
				continue
			}
			if !declared[rel] {
				diags = append(diags, Diagnostic{Code: "pap.package.undeclared-file", Severity: "warning", Scope: "package", Message: "undeclared file: " + rel})
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		completed = false
	}
	// if root unreadable, scan incomplete
	// check root read
	if _, err := os.ReadDir(root); err != nil {
		completed = false
		diags = append(diags, Diagnostic{Code: "pap.package.undeclared-scan-incomplete", Severity: "warning", Scope: "package", Message: "scan incomplete"})
	}
	if !completed {
		// ensure diagnostic present
		has := false
		for _, d := range diags {
			if d.Code == "pap.package.undeclared-scan-incomplete" {
				has = true
			}
		}
		if !has {
			diags = append(diags, Diagnostic{Code: "pap.package.undeclared-scan-incomplete", Severity: "warning", Scope: "package", Message: "scan incomplete"})
		}
	}
	return diags, completed
}

func computeVerificationRecordIdentity(report map[string]any) string {
	// clone report
	// Convert to map[string]any already.
	// Remove excluded fields:
	// evaluatedAt, durationMs, package.path, policy.path, producerClaims whole, diagnostics[].message, checks[].diagnostics[].message, checks[].witnesses[].quoteBase64
	// replace identities.verificationRecordIdentity with zero placeholder
	form := deepCopyMap(report)
	// remove top-level fields
	delete(form, "evaluatedAt")
	delete(form, "durationMs")
	// package.path
	if pkg, ok := form["package"].(map[string]any); ok {
		delete(pkg, "path")
	}
	if pol, ok := form["policy"].(map[string]any); ok {
		delete(pol, "path")
	}
	delete(form, "producerClaims")
	// diagnostics messages
	if diags, ok := form["diagnostics"].([]map[string]any); ok {
		for _, d := range diags {
			delete(d, "message")
		}
	}
	if diags, ok := form["diagnostics"].([]any); ok {
		for _, d := range diags {
			if dm, ok2 := d.(map[string]any); ok2 {
				delete(dm, "message")
			}
		}
	}
	// checks diagnostics messages and quoteBase64
	if checks, ok := form["checks"].([]any); ok {
		for _, c := range checks {
			if cm, ok2 := c.(map[string]any); ok2 {
				if ds, ok3 := cm["diagnostics"].([]any); ok3 {
					for _, d := range ds {
						if dm, ok4 := d.(map[string]any); ok4 {
							delete(dm, "message")
						}
					}
				}
				if ws, ok3 := cm["witnesses"].([]any); ok3 {
					for _, w := range ws {
						if wm, ok4 := w.(map[string]any); ok4 {
							delete(wm, "quoteBase64")
						}
					}
				}
			}
		}
	}
	// replace vri placeholder
	if ids, ok := form["identities"].(map[string]any); ok {
		ids["verificationRecordIdentity"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	canon, err := canonicalJSON(form)
	if err != nil {
		return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return H("pap.report.v1", canon)
}

func deepCopyMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return deepCopyMap(val)
	case []any:
		out := make([]any, len(val))
		for i, e := range val {
			out[i] = deepCopyValue(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(val))
		for i, e := range val {
			out[i] = deepCopyMap(e)
		}
		return out
	default:
		return v
	}
}

func computeCheckerIdentitySelf() (string, string) {
	// Try to compute from git tracked files.
	// Use git ls-files if available.
	files, deps := gatherEmbeddedClosure()
	return CheckerIdentity("pap.verifier.go", "0.1.0", files, deps)
}

func gatherFallback() ([]ClosureFile, []Dependency) {
	var files []ClosureFile
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel := filepath.ToSlash(path)
		if !includeClosureFile(rel) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files = append(files, ClosureFile{Path: rel, Content: b})
		return nil
	})
	return files, nil
}

func includeClosureFile(p string) bool {
	if strings.HasSuffix(p, "_test.go") {
		return false
	}
	if strings.HasPrefix(p, "docs/") || strings.HasPrefix(p, "pap/") || strings.HasPrefix(p, "snapshot/") {
		return false
	}
	if strings.HasSuffix(p, ".go") || p == "go.mod" || p == "go.sum" {
		return true
	}
	return false
}

func validateTrustPolicy(val any) error {
	pm, ok := val.(map[string]any)
	if !ok {
		return fmt.Errorf("not object")
	}
	allowedTop := map[string]bool{
		"trustPolicyVersion": true, "id": true, "issuedAt": true, "expiresAt": true,
		"signature": true, "keys": true, "signers": true, "checkers": true,
		"profiles": true, "requiredChecks": true, "requiredDimensions": true,
		"humanReview": true, "limits": true,
	}
	for k := range pm {
		if !allowedTop[k] {
			return fmt.Errorf("unknown field")
		}
	}
	for _, r := range []string{"trustPolicyVersion", "id", "issuedAt", "expiresAt", "signature", "keys", "signers", "checkers", "profiles", "requiredChecks", "requiredDimensions", "humanReview"} {
		if _, ok := pm[r]; !ok {
			return fmt.Errorf("missing %s", r)
		}
	}
	if v, _ := pm["trustPolicyVersion"].(string); v != "0.1" {
		return fmt.Errorf("bad version")
	}
	id, _ := pm["id"].(string)
	if id == "" || len(id) > 128 {
		return fmt.Errorf("bad id")
	}
	issued, _ := pm["issuedAt"].(string)
	expires, _ := pm["expiresAt"].(string)
	if !isRFC3339(issued) || !isRFC3339(expires) {
		return fmt.Errorf("bad time")
	}
	sig, ok := pm["signature"].(map[string]any)
	if !ok {
		return fmt.Errorf("bad signature")
	}
	mode, _ := sig["mode"].(string)
	if mode != "disabled" && mode != "optional" && mode != "required" {
		return fmt.Errorf("bad mode")
	}
	// requiredDimensions
	rd, ok := pm["requiredDimensions"].([]any)
	if !ok || len(rd) == 0 {
		return fmt.Errorf("bad requiredDimensions")
	}
	allowedDims := map[string]bool{
		"integrity": true, "integrity.package": true, "integrity.artifacts": true,
		"sources": true, "sources.integrity": true, "sources.availability": true,
		"signature": true, "signature.validity": true,
		"trust": true, "trust.signerIdentity": true, "trust.policyDecision": true,
		"trust.checkerRecognition": true, "trust.profileRecognition": true,
		"checks": true, "humanReview": true,
	}
	seen := map[string]bool{}
	for _, d := range rd {
		s, ok := d.(string)
		if !ok || !allowedDims[s] {
			return fmt.Errorf("bad dimension")
		}
		if seen[s] {
			return fmt.Errorf("dup dimension")
		}
		seen[s] = true
	}
	// requiredChecks
	rc, ok := pm["requiredChecks"].([]any)
	if !ok || len(rc) == 0 {
		return fmt.Errorf("bad requiredChecks")
	}
	seenC := map[string]bool{}
	for _, c := range rc {
		s, ok := c.(string)
		if !ok {
			return fmt.Errorf("bad check")
		}
		if seenC[s] {
			return fmt.Errorf("dup check")
		}
		seenC[s] = true
	}
	// humanReview
	hr, ok := pm["humanReview"].(map[string]any)
	if !ok {
		return fmt.Errorf("bad humanReview")
	}
	if _, ok := hr["required"].(bool); !ok {
		return fmt.Errorf("bad humanReview.required")
	}
	if _, ok := hr["maxAgeSeconds"].(int64); !ok {
		// maybe int? canonical parser returns int64
		return fmt.Errorf("bad maxAgeSeconds")
	}
	// signature required implies keys/signers
	if mode == "required" {
		keys, _ := pm["keys"].([]any)
		signers, _ := pm["signers"].([]any)
		if len(keys) == 0 || len(signers) == 0 {
			return fmt.Errorf("required needs keys")
		}
	}
	// limits
	if lim, ok := pm["limits"]; ok {
		lm, ok := lim.(map[string]any)
		if !ok {
			return fmt.Errorf("bad limits")
		}
		for k := range lm {
			// just ensure known
			known := map[string]bool{
				"manifestBytes": true, "payloadFiles": true, "fileBytes": true, "totalPayloadBytes": true,
				"pathSegments": true, "pathBytes": true, "segmentBytes": true, "jsonNesting": true,
				"jsonStringBytes": true, "claimsFiles": true, "provenanceBindings": true,
				"relationEntities": true, "relationEdges": true, "signatureEnvelopes": true,
			}
			if !known[k] {
				return fmt.Errorf("unknown limit")
			}
		}
	}
	return nil
}

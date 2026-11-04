package papverifier

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

type Report struct {
	ReportVersion string `json:"reportVersion"`
	Verifier      struct {
		ID                   string   `json:"id"`
		Version              string   `json:"version"`
		ImplementationDigest string   `json:"implementationDigest"`
		CheckerIdentities    []string `json:"checkerIdentities"`
	} `json:"verifier"`
	Package struct {
		Identity   *string `json:"identity"`
		PapVersion *string `json:"papVersion"`
		Path       *string `json:"path"`
	} `json:"package"`
	Policy struct {
		ID     *string `json:"id"`
		Digest *string `json:"digest"`
		State  string  `json:"state"`
		Path   *string `json:"path"`
	} `json:"policy"`
	EvaluatedAt string `json:"evaluatedAt"`
	// DurationMs optional
	Identifiers struct{} `json:"-"`
	// We'll use map for identities to control
	// Use generic map for report serialization? Instead define struct.
}

// We'll instead build report as map[string]any for flexibility, then marshal.
// But schema requires field order? JSON object order not semantically relevant. JCS sorts keys.
// We'll use map[string]any.

func BuildReport(pr *PackageRead, policyPath string, now time.Time, implDigest, checkerIdentity string, closureFiles []string) map[string]any {
	evaluatedAt := now.UTC().Format(time.RFC3339Nano)
	// normalize trailing zeros? RFC says fraction preserved trailing zeros stripped.
	// time.RFC3339Nano already strips trailing zeros. If no fraction, no dot.
	// But if now has nanoseconds, keep. Fine.

	// checker identities
	ciList := []string{checkerIdentity}

	// package identity pointer
	var pkgIdent *string = pr.PackageIdentity

	// papVersion pointer
	var papVer *string = pr.PapVersion

	// path pointer
	rootPath := pr.Root
	pkgPathPtr := &rootPath

	// policy
	policyState := "ABSENT"
	var policyID *string
	var policyDigest *string
	var policyPathPtr *string
	if policyPath != "" {
		policyPathPtr = &policyPath
		// validate policy? Phase 2a: we don't parse policy fully. But if provided, read and digest.
		data, err := os.ReadFile(policyPath)
		if err != nil {
			// pap.trust.policy-invalid -> no report? RFC says no report. But for simplicity, treat as absent?
			// Actually should exit 64. We'll handle in CLI before BuildReport.
		} else {
			// compute digest domain pap.trust-policy.v1 over canonical policy JSON? Need parse.
			v, err := parseStrictJSON(data, jsonNestingLimit, jsonStringLimit)
			if err != nil {
				// invalid -> CLI should have exited. Here mark invalid.
				policyState = "ABSENT"
				_ = v
			} else {
				canon, _ := CanonicalJSON(v)
				d := DomainHash("pap.trust-policy.v1", canon)
				policyDigest = &d
				// state freshness: need expiresAt/issuedAt. We'll parse basic.
				pm, _ := v.(map[string]any)
				state := policyFreshness(pm, now)
				policyState = state
				if id, ok := pm["id"].(string); ok {
					policyID = &id
				}
			}
		}
		_ = data
	}

	// identities
	artifactsArr := []map[string]any{}
	for _, a := range pr.Artifacts {
		comp := a.Computed
		artifactsArr = append(artifactsArr, map[string]any{
			"id":       a.ID,
			"declared": a.Declared,
			"computed": comp,
		})
	}
	sourcesArr := []map[string]any{}
	for _, s := range pr.Sources {
		sourcesArr = append(sourcesArr, map[string]any{
			"id":       s.ID,
			"declared": s.Declared,
			"computed": s.Computed,
		})
	}
	// normalized input digest
	var nid any = pr.NormalizedInputDigest
	if pr.NormalizedInputDigest == nil {
		nid = nil
	}
	// extension closure
	var ecd any = pr.ExtensionClosureDigest
	if pr.ExtensionClosureDigest == nil {
		ecd = nil
	}

	// dimensions
	integrityPackage := pr.IntegrityPackage
	if integrityPackage == "" {
		integrityPackage = "PASS"
	}
	integrityArtifacts := pr.IntegrityArtifacts
	if integrityArtifacts == "" {
		integrityArtifacts = "NOT_EVALUATED"
	}
	sourcesIntegrity := pr.SourcesIntegrity
	if sourcesIntegrity == "" {
		sourcesIntegrity = "NOT_EVALUATED"
	}
	sourcesAvailability := pr.SourcesAvailability
	if sourcesAvailability == "" {
		sourcesAvailability = "NOT_APPLICABLE"
	}

	// checks results
	checkResults := []map[string]any{}
	checksArray := []map[string]any{} // top-level checks (check records) empty for 2a
	// Determine check outcomes
	unsupportedVersion := pr.UnsupportedVersion || pr.NewerMinor
	for _, cs := range pr.CheckSpecs {
		outcome := "NOT_EVALUATED"
		// if unknown check id (not one of known) -> UNSUPPORTED
		if !isKnownCheck(cs.ID) {
			outcome = "UNSUPPORTED"
		} else if unsupportedVersion {
			outcome = "NOT_EVALUATED"
		} else {
			// Phase 2a doesn't implement checks -> NOT_EVALUATED?
			// But F09 expects known check PASS in full cases (not compared in 2a).
			// We'll keep NOT_EVALUATED.
			outcome = "NOT_EVALUATED"
		}
		checkResults = append(checkResults, map[string]any{
			"checkId":  cs.ID,
			"outcome":  outcome,
			"required": cs.Required,
		})
		// diagnostic for unsupported
		if outcome == "UNSUPPORTED" && isKnownCheck(cs.ID) == false {
			// pap.check.unsupported
		}
	}
	// Add diagnostics for unsupported checks
	for _, cs := range pr.CheckSpecs {
		if !isKnownCheck(cs.ID) {
			addDiag(pr, "pap.check.unsupported", "warning", "package", cs.ID)
		}
	}
	// diagnostics for not-evaluated known checks when version unsupported or missing inputs
	if unsupportedVersion {
		for _, cs := range pr.CheckSpecs {
			if isKnownCheck(cs.ID) {
				addDiag(pr, "pap.check.not-evaluated", "warning", "package", cs.ID)
			}
		}
	}
	// if missing artifact, not-evaluated
	if pr.IntegrityArtifacts == "FAIL" {
		for _, cs := range pr.CheckSpecs {
			if isKnownCheck(cs.ID) {
				// add not-evaluated diagnostic? F26 expects pap.check.not-evaluated
				addDiag(pr, "pap.check.not-evaluated", "warning", "package", cs.ID)
			}
		}
	}
	// if limit exceeded, not-evaluated
	if pr.LimitExceeded {
		for _, cs := range pr.CheckSpecs {
			addDiag(pr, "pap.check.not-evaluated", "warning", "package", cs.ID)
		}
	}

	// required checks
	requiredChecks := []string{}
	for _, cs := range pr.CheckSpecs {
		if cs.Required {
			requiredChecks = append(requiredChecks, cs.ID)
		}
	}
	// policy required checks? none (no policy parsing).

	// required dimensions: implied by required checks
	reqDimsSet := map[string]bool{}
	for _, rc := range requiredChecks {
		if rc == "pap.check.digest-integrity/1" || strings.HasPrefix(rc, "pap.check.digest-integrity/") {
			reqDimsSet["integrity"] = true
			reqDimsSet["checks"] = true
		}
		if rc == "pap.check.source-quote/1" || strings.HasPrefix(rc, "pap.check.source-quote/") {
			reqDimsSet["sources"] = true
			reqDimsSet["checks"] = true
		}
		if rc == "pap.check.relation-consistency/1" || strings.HasPrefix(rc, "pap.check.relation-consistency/") {
			reqDimsSet["checks"] = true
		}
		// unknown required check -> checks
		if !isKnownCheck(rc) {
			reqDimsSet["checks"] = true
		}
	}
	// policy requiredDimensions none
	// convert to sorted list per Appendix B enumerable order
	dimOrder := []string{"integrity", "integrity.package", "integrity.artifacts", "sources", "sources.integrity", "sources.availability", "signature", "signature.validity", "trust", "trust.signerIdentity", "trust.policyDecision", "trust.checkerRecognition", "trust.profileRecognition", "checks", "humanReview"}
	requiredDims := []string{}
	for _, d := range dimOrder {
		// only root dims? requiredDimensions uses root entries per E.4: integrity, sources, checks.
		if (d == "integrity" || d == "sources" || d == "signature" || d == "trust" || d == "checks" || d == "humanReview") && reqDimsSet[d] {
			requiredDims = append(requiredDims, d)
		}
	}
	// Note: requiredDimensions in E.4 lists integrity, sources, checks (root). Good.

	// If no required checks -> empty-check-specs, but requiredDims empty. coverage full false.

	// dimensionsEvaluated count
	// decided statuses
	isDecided := func(status string) bool {
		switch status {
		case "NOT_EVALUATED", "UNKNOWN", "UNAVAILABLE", "INCOMPLETE", "UNSUPPORTED":
			return false
		}
		return true
	}
	dimsEvaluated := 0
	// map dimension root to decided
	// integrity decided if package & artifacts decided?
	integrityDecided := isDecided(integrityPackage) && isDecided(integrityArtifacts)
	sourcesDecided := isDecided(sourcesIntegrity) && isDecided(sourcesAvailability) // availability may be NOT_APPLICABLE decided? NOT_APPLICABLE decided where allowed. isDecided returns true for NOT_APPLICABLE (not in false list). Good.
	checksDecided := true
	for _, cr := range checkResults {
		out := cr["outcome"].(string)
		if out != "PASS" && out != "FAIL" {
			checksDecided = false
		}
	}
	// required checks all PASS/FAIL for checks decided
	if len(requiredChecks) == 0 {
		checksDecided = false
	}
	for _, rd := range requiredDims {
		switch rd {
		case "integrity":
			if integrityDecided {
				dimsEvaluated++
			}
		case "sources":
			if sourcesDecided {
				dimsEvaluated++
			}
		case "checks":
			if checksDecided {
				dimsEvaluated++
			}
		}
	}

	// check counters among required checks
	checksPassed := 0
	checksFailed := 0
	checksUnsupported := 0
	checksNotEvaluated := 0
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		// find outcome
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		switch out {
		case "PASS":
			checksPassed++
		case "FAIL":
			checksFailed++
		case "UNSUPPORTED":
			checksUnsupported++
		case "NOT_EVALUATED":
			checksNotEvaluated++
		}
	}
	checksEvaluated := checksPassed + checksFailed

	// coverage full
	undeclaredComplete := pr.UndeclaredScanComplete
	full := true
	if checksNotEvaluated != 0 || checksUnsupported != 0 {
		full = false
	}
	if dimsEvaluated != len(requiredDims) {
		full = false
	}
	if !undeclaredComplete {
		full = false
	}
	if pr.LimitExceeded {
		full = false
	}
	if len(requiredChecks) == 0 && len(requiredDims) == 0 {
		full = false
	}
	// empty required set
	emptyRequired := (len(requiredChecks) == 0 && len(requiredDims) == 0)

	pr.CoverageFull = full

	// verdict
	verdict := computeVerdict(pr, checkResults, requiredChecks, requiredDims, integrityPackage, integrityArtifacts, sourcesIntegrity, sourcesAvailability, emptyRequired, full)

	// limitations
	// diagnostics dedup? keep as is
	diags := pr.Diagnostics
	if diags == nil {
		diags = []Diagnostic{}
	}
	limitations := pr.Limitations
	if limitations == nil {
		limitations = []Limitation{}
	}

	// dimensions object
	dims := map[string]any{
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
			"signerIdentity":     "NOT_APPLICABLE",
			"policyDecision":     "NOT_EVALUATED",
			"checkerRecognition": "NOT_EVALUATED",
			"profileRecognition": "NOT_EVALUATED",
		},
		"checks": map[string]any{
			"results": checkResults,
		},
		"humanReview": map[string]any{
			"status": "NOT_APPLICABLE",
		},
		"semanticTruth":       "NOT_EVALUATED",
		"legalEnforceability": "NOT_EVALUATED",
	}
	if policyState == "ABSENT" {
		dims["trust"].(map[string]any)["signerIdentity"] = "NOT_APPLICABLE"
	}

	// if policy present, could set checker/profile recognition based on allowlists; Phase 2a no. Keep NOT_EVALUATED.

	// producer claims
	producerClaims := map[string]any{
		"present": false,
		"trusted": false,
	}
	if pr.HasProducerReport {
		producerClaims["present"] = true
		// comparison not implemented; empty
		producerClaims["comparison"] = []map[string]any{}
	}

	report := map[string]any{
		"reportVersion": "0.1",
		"verifier": map[string]any{
			"id":                   CheckerID,
			"version":              CheckerVersion,
			"implementationDigest": implDigest,
			"checkerIdentities":    ciList,
		},
		"package": map[string]any{
			"identity":   pkgIdent,
			"papVersion": papVer,
			"path":       pkgPathPtr,
		},
		"policy": map[string]any{
			"id":     policyID,
			"digest": policyDigest,
			"state":  policyState,
			"path":   policyPathPtr,
		},
		"evaluatedAt": evaluatedAt,
		"identities": map[string]any{
			"packageIdentity":            pkgIdent,
			"artifacts":                  artifactsArr,
			"sources":                    sourcesArr,
			"normalizedInputDigest":      nid,
			"extensionClosureDigest":     ecd,
			"checkerIdentity":            checkerIdentity,
			"verificationRecordIdentity": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		"dimensions":     dims,
		"checks":         checksArray,
		"producerClaims": producerClaims,
		"coverage": map[string]any{
			"requiredChecks":      requiredChecks,
			"checksEvaluated":     checksEvaluated,
			"checksPassed":        checksPassed,
			"checksFailed":        checksFailed,
			"checksUnsupported":   checksUnsupported,
			"checksNotEvaluated":  checksNotEvaluated,
			"requiredDimensions":  requiredDims,
			"dimensionsEvaluated": dimsEvaluated,
			"full":                full,
		},
		"limitations": limitations,
		"verdict":     verdict,
		"diagnostics": diags,
	}
	// verification record identity: compute from identity form with placeholder already set.
	vri := computeVerificationRecordIdentity(report)
	report["identities"].(map[string]any)["verificationRecordIdentity"] = vri

	return report
}

func isKnownCheck(id string) bool {
	return id == "pap.check.digest-integrity/1" ||
		id == "pap.check.source-quote/1" ||
		id == "pap.check.relation-consistency/1"
}

func computeVerdict(pr *PackageRead, checkResults []map[string]any, requiredChecks, requiredDims []string, integrityPackage, integrityArtifacts, sourcesIntegrity, sourcesAvailability string, emptyRequired, full bool) string {
	// FAIL rule
	fail := false
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		// find outcome
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		if out == "FAIL" {
			fail = true
		}
	}
	if integrityPackage == "FAIL" || integrityArtifacts == "FAIL" {
		fail = true
	}
	if sourcesIntegrity == "FAIL" {
		fail = true
	}
	// claim mismatch already integrity package FAIL
	if fail {
		return "FAIL"
	}
	// UNTRUSTED: no trust policy in 2a, none
	// UNSUPPORTED
	unsupported := false
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		if out == "UNSUPPORTED" {
			unsupported = true
		}
	}
	if pr.UnsupportedVersion || pr.NewerMinor {
		unsupported = true
	}
	if len(pr.RequiredFeatures) > 0 {
		unsupported = true
	}
	// critical extensions
	for _, v := range pr.Extensions {
		em, _ := v.(map[string]any)
		if crit, _ := em["critical"].(bool); crit {
			unsupported = true
		}
	}
	if unsupported {
		return "UNSUPPORTED"
	}
	// INCOMPLETE
	incomplete := false
	// required dimension not evaluated/unknown/unavailable/stale/incomplete
	for _, rd := range requiredDims {
		// check status
		var status string
		switch rd {
		case "integrity":
			if integrityPackage != "PASS" || integrityArtifacts != "PASS" {
				// if NOT_EVALUATED etc.
				if integrityPackage != "PASS" {
					status = integrityPackage
				}
				if integrityArtifacts != "PASS" {
					status = integrityArtifacts
				}
			}
		case "sources":
			if sourcesIntegrity != "PASS" {
				status = sourcesIntegrity
			}
			if sourcesAvailability != "PASS" && sourcesAvailability != "NOT_APPLICABLE" {
				status = sourcesAvailability
			}
		case "checks":
			for _, cs := range pr.CheckSpecs {
				if !cs.Required {
					continue
				}
				out := "NOT_EVALUATED"
				for _, cr := range checkResults {
					if cr["checkId"] == cs.ID {
						out = cr["outcome"].(string)
					}
				}
				if out == "NOT_EVALUATED" {
					status = "NOT_EVALUATED"
				}
			}
		}
		if status != "" && status != "PASS" {
			incomplete = true
		}
	}
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		if out == "NOT_EVALUATED" {
			incomplete = true
		}
	}
	if emptyRequired {
		incomplete = true
	}
	if !full {
		incomplete = true
	}
	if pr.LimitExceeded {
		incomplete = true
	}
	// policy stale none
	if incomplete {
		return "INCOMPLETE"
	}
	// NOT_EVALUATED degenerate: if no required check evaluated at all
	allNotEval := true
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		if out != "NOT_EVALUATED" {
			allNotEval = false
		}
	}
	if len(requiredChecks) > 0 && allNotEval {
		return "NOT_EVALUATED"
	}
	// PASS: all required checks PASS and dims positive. But our checks are NOT_EVALUATED, so won't reach.
	pass := true
	for _, cs := range pr.CheckSpecs {
		if !cs.Required {
			continue
		}
		out := "NOT_EVALUATED"
		for _, cr := range checkResults {
			if cr["checkId"] == cs.ID {
				out = cr["outcome"].(string)
			}
		}
		if out != "PASS" {
			pass = false
		}
	}
	if integrityPackage != "PASS" || integrityArtifacts != "PASS" {
		pass = false
	}
	if sourcesIntegrity != "PASS" {
		pass = false
	}
	if !full {
		pass = false
	}
	if pass && len(requiredChecks) > 0 {
		return "PASS"
	}
	// default
	return "INCOMPLETE"
}

func policyFreshness(pm map[string]any, now time.Time) string {
	// issuedAt/expiresAt
	issued, _ := pm["issuedAt"].(string)
	expires, _ := pm["expiresAt"].(string)
	if issued != "" {
		t, err := time.Parse(time.RFC3339Nano, issued)
		if err == nil && now.Before(t) {
			return "STALE"
		}
	}
	if expires != "" {
		t, err := time.Parse(time.RFC3339Nano, expires)
		if err == nil && now.After(t) {
			return "STALE"
		}
	}
	return "FRESH"
}

func computeVerificationRecordIdentity(report map[string]any) string {
	// Build identity form: copy report, remove excluded fields, replace verificationRecordIdentity with zero.
	// We'll marshal to map via JSON roundtrip then manipulate.
	b, _ := json.Marshal(report)
	var form map[string]any
	json.Unmarshal(b, &form)

	// remove excluded top-level fields
	delete(form, "evaluatedAt")
	// durationMs not present
	delete(form, "package") //? package.path excluded but package.identity/papVersion kept. Need remove only path.
	// We removed whole package; instead handle carefully. Let's redo.
	// Re-unmarshal fresh
	json.Unmarshal(b, &form)

	// package.path
	if pkg, ok := form["package"].(map[string]any); ok {
		delete(pkg, "path")
	}
	// policy.path
	if pol, ok := form["policy"].(map[string]any); ok {
		delete(pol, "path")
	}
	// producerClaims whole block
	delete(form, "producerClaims")
	// diagnostics messages
	if diags, ok := form["diagnostics"].([]any); ok {
		for _, d := range diags {
			if dm, ok := d.(map[string]any); ok {
				delete(dm, "message")
			}
		}
	}
	// checks[] diagnostics messages and quoteBase64
	if checks, ok := form["checks"].([]any); ok {
		for _, c := range checks {
			if cm, ok := c.(map[string]any); ok {
				// diagnostics
				if diags, ok := cm["diagnostics"].([]any); ok {
					for _, d := range diags {
						if dm, ok := d.(map[string]any); ok {
							delete(dm, "message")
						}
					}
				}
				// witnesses quoteBase64
				if ws, ok := cm["witnesses"].([]any); ok {
					for _, w := range ws {
						if wm, ok := w.(map[string]any); ok {
							delete(wm, "quoteBase64")
						}
					}
				}
			}
		}
	}
	// identities.verificationRecordIdentity placeholder
	if ids, ok := form["identities"].(map[string]any); ok {
		ids["verificationRecordIdentity"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	// evaluatedAt already deleted
	delete(form, "evaluatedAt")
	// durationMs
	delete(form, "durationMs")
	// effectiveLimits? If present, kept (part of identity). Not in our report.

	canon, err := CanonicalJSON(form)
	if err != nil {
		// fallback zero
		return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}
	return DomainHash("pap.report.v1", canon)
}

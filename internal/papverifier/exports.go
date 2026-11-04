package papverifier

import "time"

func ResolvePackageRootExported(pkg string) (string, error) {
	return resolvePackageRoot(pkg)
}

// ReadPackageExported wraps readPackage.
func ReadPackageExported(pkg string) (*PackageRead, int, error) {
	return readPackage(pkg)
}

func ParseStrictJSONExported(data []byte, maxDepth, maxString int) (any, error) {
	return parseStrictJSON(data, maxDepth, maxString)
}

var JSONNestingLimit = jsonNestingLimit
var JSONStringLimit = jsonStringLimit

// Export BuildReport already exported.
// Export time? no.

// Wrap now? no.

func BuildReportExported(pr *PackageRead, policyPath string, now time.Time, implDigest, checkerIdentity string) map[string]any {
	return BuildReport(pr, policyPath, now, implDigest, checkerIdentity, nil)
}

func ExtensionClosureDigestExported(kind, id, version string, files []ClosureFile, deps []ClosureDep) string {
	return ExtensionClosureDigest(kind, id, version, files, deps)
}

func CheckerIdentityExported(id, version, impl string) string {
	return CheckerIdentity(id, version, impl)
}

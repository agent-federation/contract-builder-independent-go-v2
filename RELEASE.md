# PAP Phase 2a experimental — Go release

- module: `github.com/agent-federation/contract-builder-independent-go-v2`
- experiment: `PAP-GO-P2A-003`; Gate 3 result commit: `8d49d69`
- scope: Phase 2a only; not full PAP/Tier B conformance
- license: MIT

## Build

```bash
go build -o pap .
```

## Install (after registry/version publication)

```bash
go install github.com/agent-federation/contract-builder-independent-go-v2@v0.1.0-phase2a.3
```

## Evidence

- 19/19 full + 36/36 identity, zero comparison findings;
- external Gate 3 audit: APPROVED UNCONDITIONALLY (Phase 2a);
- release metadata changes `go.mod`, so this release has a new checker identity; the Gate 3 tag
  remains `pap-go-p2a-003-result`.

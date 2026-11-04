package main

type Limits struct {
	ManifestBytes     int
	PayloadFiles      int
	FileBytes         int
	TotalPayloadBytes int
	PathSegments      int
	PathBytes         int
	SegmentBytes      int
	JSONNesting       int
	JSONStringBytes   int
	ClaimsFiles       int
	ProvenanceBindings int
	RelationEntities  int
	RelationEdges     int
	SignatureEnvelopes int
}

func DefaultLimits() Limits {
	return Limits{
		ManifestBytes:      1 * 1024 * 1024,
		PayloadFiles:       4096,
		FileBytes:          256 * 1024 * 1024,
		TotalPayloadBytes:  1 * 1024 * 1024 * 1024,
		PathSegments:       16,
		PathBytes:          255,
		SegmentBytes:       255,
		JSONNesting:        64,
		JSONStringBytes:    16 * 1024 * 1024,
		ClaimsFiles:        16,
		ProvenanceBindings: 100000,
		RelationEntities:   100000,
		RelationEdges:      1000000,
		SignatureEnvelopes: 32,
	}
}

// Package frameworks embeds the data-driven compliance packs so the binary is
// self-contained. Adding a pack means dropping a *.yaml here — no code change
// (ARCHITECTURE.md §9.1).
package frameworks

import "embed"

// Packs holds every shipped *.yaml compliance pack.
//
//go:embed *.yaml
var Packs embed.FS

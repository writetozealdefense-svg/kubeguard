// Package api holds the public, version-stable types KubeGuard emits and that
// external consumers — the USP control plane, JSON/SARIF readers, and the HTML
// dashboard — depend on (ARCHITECTURE.md §4.2, §12.4).
//
// Stability contract: changes are additive within a major version. Nothing in
// this package may import internal/* packages.
package api

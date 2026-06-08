// Package harden emits the least-privilege baseline bundle (PSA, default-deny
// NetworkPolicy, scoped RBAC, Kyverno/Gatekeeper policies, a hardened
// Deployment, and a checklist) plus per-finding fix snippets
// (ARCHITECTURE.md §11).
package harden

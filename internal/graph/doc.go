// Package graph builds a typed inventory of loaded resources and resolves the
// relationships the engines depend on: Pod→SA, SA→Role/ClusterRole via
// bindings, Service→workload by selector, Namespace→NetworkPolicy
// (ARCHITECTURE.md §6).
package graph

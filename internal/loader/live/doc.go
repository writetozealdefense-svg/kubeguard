// Package live ingests Kubernetes resources from a cluster via a read-only
// client-go client (ARCHITECTURE.md §5.2). It never creates, patches, or
// deletes cluster resources.
package live

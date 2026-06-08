// Package webhook implements a controller-runtime validating admission webhook
// that denies pods violating the active profile. It admits or denies only and
// never mutates cluster resources (ARCHITECTURE.md §14).
package webhook

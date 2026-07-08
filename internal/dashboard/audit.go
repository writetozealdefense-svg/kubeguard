package dashboard

import "sync"

// AuditEntry is one append-only record of a privileged action (NFR-1 / D3).
// Tenant-partitioned; never holds secret values.
type AuditEntry struct {
	At       string `json:"at"`
	Subject  string `json:"subject"`
	Tenant   string `json:"tenant"`
	Action   string `json:"action"`
	Resource string `json:"resource,omitempty"`
	Result   string `json:"result"` // "allowed" | "denied"
}

// AuditLog is the append-only audit boundary. The in-memory implementation
// backs D3; Squad P1 persists it to Postgres behind this same interface.
// Entries are never updated or deleted.
type AuditLog interface {
	Write(AuditEntry)
	List(tenant string) []AuditEntry
}

// MemAuditLog is an in-memory, append-only, tenant-partitioned audit log.
type MemAuditLog struct {
	mu      sync.RWMutex
	entries map[string][]AuditEntry
}

// NewMemAuditLog builds an empty audit log.
func NewMemAuditLog() *MemAuditLog {
	return &MemAuditLog{entries: map[string][]AuditEntry{}}
}

// Write appends an entry (append-only — existing entries are never mutated).
func (a *MemAuditLog) Write(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries[e.Tenant] = append(a.entries[e.Tenant], e)
}

// List returns a tenant's audit entries in write order.
func (a *MemAuditLog) List(tenant string) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]AuditEntry{}, a.entries[tenant]...)
}

// PurgeTenant removes a tenant's audit entries (DPDP erasure — audit entries are
// personal data too). The proof-of-erasure record lives in the acting operator's
// tenant, not the erased one, so it survives this purge.
func (a *MemAuditLog) PurgeTenant(tenant string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.entries, tenant)
}

// tenantPurger is implemented by audit logs that can erase a tenant's entries
// (MemAuditLog). The pg audit log erases audit rows inside Store.DeleteTenant,
// so it does not implement this — the erasure handler calls whichever applies.
type tenantPurger interface {
	PurgeTenant(tenant string)
}

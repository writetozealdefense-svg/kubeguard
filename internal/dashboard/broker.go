package dashboard

import "sync"

// Event is a server-sent event published to dashboard subscribers (scan
// lifecycle + posture updates). Mirrors the StreamEvent schema in openapi.yaml.
type Event struct {
	Type      string  `json:"type"`
	ClusterID string  `json:"clusterId,omitempty"`
	ScanID    string  `json:"scanId,omitempty"`
	Progress  float64 `json:"progress,omitempty"`
	Message   string  `json:"message,omitempty"`
}

type subscriber struct {
	tenant string
	ch     chan Event
}

// Broker is a tenant-scoped pub/sub fan-out for SSE. Publishes are
// non-blocking: a slow subscriber drops events rather than stalling a scan.
type Broker struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

// NewBroker builds an empty broker.
func NewBroker() *Broker {
	return &Broker{subs: map[*subscriber]struct{}{}}
}

// Subscribe registers a subscriber for a tenant and returns its channel plus an
// unsubscribe func that closes the channel.
func (b *Broker) Subscribe(tenant string) (<-chan Event, func()) {
	s := &subscriber{tenant: tenant, ch: make(chan Event, 16)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s.ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
		b.mu.Unlock()
	}
}

// Publish fans an event out to every subscriber of the same tenant. Never
// blocks: if a subscriber's buffer is full, the event is dropped for it.
func (b *Broker) Publish(tenant string, ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if s.tenant != tenant {
			continue
		}
		select {
		case s.ch <- ev:
		default:
		}
	}
}

// subscriberCount reports how many subscribers a tenant has (test helper).
func (b *Broker) subscriberCount(tenant string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := 0
	for s := range b.subs {
		if s.tenant == tenant {
			n++
		}
	}
	return n
}

package pipeline

import (
	"sync"
)

// Message is one live update pushed to connected dashboards.
type Message struct {
	Type string `json:"type"` // flow | dns | device | finding | status
	Data any    `json:"data"`
}

// Bus fans live updates out to every connected client.
//
// It is deliberately lossy. A dashboard that cannot keep up with a busy network
// gets the newest events and drops the backlog, because a live view showing
// stale traffic is worse than one showing a gap, and because a slow websocket
// must never be able to stall ingest.
type Bus struct {
	mu   sync.RWMutex
	subs map[chan Message]struct{}
	// Depth is the per-subscriber buffer.
	depth int
}

// NewBus returns a bus with the given per-subscriber queue depth.
func NewBus(depth int) *Bus {
	if depth <= 0 {
		depth = 256
	}
	return &Bus{subs: make(map[chan Message]struct{}), depth: depth}
}

// Subscribe registers a listener and returns it with its cancel function.
func (b *Bus) Subscribe() (<-chan Message, func()) {
	ch := make(chan Message, b.depth)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			b.mu.Unlock()
			close(ch)
		})
	}
}

// Publish delivers a message to every subscriber, dropping the oldest queued
// message for any subscriber that has fallen behind.
func (b *Bus) Publish(m Message) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- m:
		default:
			// Make room by discarding the stalest message, then retry once.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- m:
			default:
			}
		}
	}
}

// Subscribers reports the current listener count.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

package rate

import (
	"errors"
	"sync"
	"time"
)

// Limiter provides a per-client rate limiter, where clients are identified
// by a unique ID.
type Limiter interface {
	// Wait blocks until the operation should be allowed to continue for
	// the given ID, or returns an error if the operation should not be
	// allowed (e.g. because there are too many concurrent waiters).
	Wait(clientID string) error
}

// NewLimiter creates a new rate limiter which allows rate events per second,
// no bursting, and at most maxWaiters waiters.
func NewLimiter(rate float64, maxWaiters int) Limiter {
	return &limiter{
		dur:        time.Duration(float64(time.Second) / rate),
		maxWaiters: maxWaiters,
		entries:    map[string]*entry{},
	}
}

type limiter struct {
	dur        time.Duration // how long to wait between allowing events
	maxWaiters int

	mu      sync.Mutex // protects entries as well as all values of entries
	entries map[string]*entry
}

type entry struct {
	waiters int
	waitCh  chan struct{}
}

func (l *limiter) Wait(clientID string) error {
	// Get entry for client, creating if necessary.
	l.mu.Lock()
	e := l.entries[clientID]
	if e == nil {
		e = &entry{}
		l.entries[clientID] = e
	}

	// Get current wait channel, increment waiters if we're going to
	// be waiting, and create the next wait channel.
	waitCh := e.waitCh
	if waitCh != nil {
		if e.waiters == l.maxWaiters {
			l.mu.Unlock()
			return errors.New("too many concurrent events")
		}
		e.waiters++
	}
	nextWaitCh := make(chan struct{})
	e.waitCh = nextWaitCh
	l.mu.Unlock()

	// Wait if needed until we're ready to be released, then set up a timer
	// to release the next in the queue or clean up if no one is enqueued.
	if waitCh != nil {
		<-waitCh
	}
	time.AfterFunc(l.dur, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		close(nextWaitCh)
		if e.waiters == 0 {
			delete(l.entries, clientID)
		}
		e.waiters--
	})
	return nil
}

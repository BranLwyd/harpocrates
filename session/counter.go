package session

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Stores a uint32 counter keyed by an opaque string, and serializes changes
// disk. Used for storing & retrieving U2F counters. It is safe for concurrent
// use from multiple goroutines.
type CounterStore struct {
	mu      sync.RWMutex // protects store, file named by ctrFile
	store   map[string]uint32
	ctrFile string
}

func NewCounterStore(counterFile string) (*CounterStore, error) {
	f, err := os.Open(counterFile)
	if err != nil {
		return nil, fmt.Errorf("could not open U2F counter file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Error closing counter file: %v", err)
		}
	}()

	s := make(map[string]interface{})
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, fmt.Errorf("could not parse U2F counter file: %v", err)
	}
	store := make(map[string]uint32)
	for k, v := range s {
		strV, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("could not parse value for handle %q", k)
		}
		numV, err := strconv.ParseUint(strV, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("could not parse value for handle %q", k)
		}
		store[k] = uint32(numV)
	}

	return &CounterStore{
		store:   store,
		ctrFile: counterFile,
	}, nil
}

// NewMemoryCounterStore creates a new counter store that has no backing file.
// It should be used only for testing.
func NewMemoryCounterStore() *CounterStore {
	return &CounterStore{
		store: make(map[string]uint32),
	}
}

// Get gets the value associated with the given handle. It returns 0 if no such
// handle exists.
func (c CounterStore) Get(handle string) uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store[handle]
}

// Set sets the value associated with the given handle. If it returns a non-nil
// error, the store is left unmodified.
func (c *CounterStore) Set(handle string, val uint32) (retErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update file.
	if c.ctrFile != "" {
		s := make(map[string]string)
		for k, v := range c.store {
			if k == handle {
				continue
			}
			s[k] = strconv.FormatUint(uint64(v), 10)
		}
		if val != 0 {
			s[handle] = strconv.FormatUint(uint64(val), 10)
		}

		f, err := ioutil.TempFile(filepath.Dir(c.ctrFile), ".harp_u2fctr")
		if err != nil {
			return fmt.Errorf("could not create temporary file: %v", err)
		}

		closeAttempted := false
		defer func() {
			if retErr != nil {
				if !closeAttempted {
					if err := f.Close(); err != nil {
						log.Printf("Could not close temporary file: %v", err)
					}
				}
				if err := os.Remove(f.Name()); err != nil {
					log.Printf("Could not remove temporary file: %v", err)
				}
			}
		}()

		if err := json.NewEncoder(f).Encode(s); err != nil {
			return fmt.Errorf("could not write U2F counter file: %v", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("could not close U2F counter file: %v", err)
		}
		if err := os.Rename(f.Name(), c.ctrFile); err != nil {
			return fmt.Errorf("could not rename U2F counter file: %v", err)
		}
	}

	// Update in-memory representation.
	if val == 0 {
		delete(c.store, handle)
	} else {
		c.store[handle] = val
	}
	return nil
}

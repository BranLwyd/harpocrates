// Package counter provides functionality for tracking of multi-factor authentication counters.
package counter

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/golang/protobuf/proto"

	cpb "github.com/BranLwyd/harpocrates/harpd/proto/counter_go_proto"
)

// Store stores a uint32 counter keyed by an opaque string, and serializes changes to disk. Used for
// storing & retrieving multi-factor authentication counters. It is safe for concurrent use from
// multiple goroutines.
type Store struct {
	mu      sync.RWMutex // protects store, file named by ctrFile
	ctrs    *cpb.Counters
	ctrFile string
}

func NewStore(counterFile string) (*Store, error) {
	// Parse the counter file.
	counterFile = filepath.Clean(counterFile)
	ctrs := &cpb.Counters{}
	cfBytes, err := ioutil.ReadFile(counterFile)
	switch {
	case err == nil:
		if err := proto.Unmarshal(cfBytes, ctrs); err != nil {
			return nil, fmt.Errorf("could not parse MFA counter file: %v", err)
		}

	case os.IsNotExist(err):
		// Just start up, logging to notify that the counter file is new.
		log.Printf("Creating counter file %q", counterFile)

	default:
		return nil, fmt.Errorf("could not read MFA counter file: %v", err)
	}

	// Create a store, then write to make sure we can update the counter file.
	s := &Store{
		ctrs:    ctrs,
		ctrFile: counterFile,
	}
	if err := s.write(); err != nil {
		return nil, fmt.Errorf("could not write MFA counters: %v", err)
	}
	return s, nil
}

// NewMemoryStore creates a new counter store that has no backing file.
// It should be used only for testing.
func NewMemoryStore() *Store {
	return &Store{
		ctrs: &cpb.Counters{},
	}
}

// Get gets the value associated with the given handle. It returns 0 if no such
// handle exists.
func (s *Store) Get(handle string) uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ctrs.Counter[handle]
}

// Set sets the value associated with the given handle. If it returns a non-nil
// error, the store is left unmodified.
func (s *Store) Set(handle string, val uint32) (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	setVal := func(val uint32) {
		if s.ctrs.Counter == nil {
			s.ctrs.Counter = map[string]uint32{}
		}
		if val == 0 {
			delete(s.ctrs.Counter, handle)
		} else {
			s.ctrs.Counter[handle] = val
		}
	}
	// Roll forward, rolling back on error.
	defer func(oldVal uint32) {
		if retErr != nil {
			setVal(oldVal)
		}
	}(s.ctrs.Counter[handle])
	setVal(val)

	// Write to disk.
	if err := s.write(); err != nil {
		return fmt.Errorf("could not write MFA counters: %v", err)
	}
	return nil
}

func (s *Store) write() error {
	if s.ctrFile == "" {
		// In-memory only.
		return nil
	}

	ctrBytes, err := proto.Marshal(s.ctrs)
	if err != nil {
		return fmt.Errorf("could not serialize MFA counters: %v", err)
	}
	tempFile, err := ioutil.TempFile(filepath.Dir(s.ctrFile), ".harp_mfactr")
	if err != nil {
		return fmt.Errorf("could not create temporary file: %v", err)
	}
	tempFilename := tempFile.Name()
	defer os.Remove(tempFilename)
	defer tempFile.Close()
	if _, err := tempFile.Write(ctrBytes); err != nil {
		return fmt.Errorf("could not write MFA counter file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("could not close MFA counter file: %v", tempFile.Name(), err)
	}
	if err := os.Rename(tempFilename, s.ctrFile); err != nil {
		return fmt.Errorf("could not rename MFA counter file: %v", err)
	}
	return nil
}

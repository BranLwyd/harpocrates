// Package cert contains functionality for working with TLS certificates.
package cert

import (
	"crypto/tls"
	"log"
	"sync"
	"time"
)

// Cache is an automatically-reloading TLS certificate cache backed from disk.
// It can be used to pick up changes to an on-disk certificate, handy if the
// certificate is short-lived and automatically refreshed on occasion (as the
// certificates from e.g. Let's Encrypt typically are). It is safe for
// concurrent use from multiple goroutines.
type Cache struct {
	certFile string
	keyFile  string

	certMu sync.RWMutex
	cert   *tls.Certificate
}

// NewCache creates a new certificate Cache, using the given files on disk as
// the certificate & key files, attempting to automatically refresh the cert on
// the given interval. Calling NewCache attempts to read the certificate
// immediately; failure to read the certificate during this call causes an
// error to be returned.
func NewCache(certFile string, keyFile string, refreshInterval time.Duration) (*Cache, error) {
	c := &Cache{
		certFile: certFile,
		keyFile:  keyFile,
	}

	if err := c.set(); err != nil {
		return nil, err
	}

	go func() {
		for range time.Tick(refreshInterval) {
			log.Print("Reloading certificate")
			if err := c.set(); err != nil {
				log.Printf("Could not reload certificate: %v", err)
			}
		}
	}()

	return c, nil
}

// Get gets the current TLS certificate stored by the cache. It will never
// block.
func (c *Cache) Get() *tls.Certificate {
	c.certMu.RLock()
	defer c.certMu.RUnlock()
	return c.cert
}

func (c *Cache) set() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}

	c.certMu.Lock()
	defer c.certMu.Unlock()
	c.cert = &cert
	return nil
}

// Package random contains functionality to generate cryptographically-strong random values.
package random

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"sync"
)

// String returns a random string of the given length, sampled from the given character set.
// The character set is not checked for uniqueness: characters represented multiple times will be
// correspondingly more likely.
func String(n int, charset string) (string, error) {
	var sb strings.Builder
	sb.Grow(n)

	rnd := generator(uint64(len(charset)))
	for sb.Len() < n {
		i, err := rnd()
		if err != nil {
			return "", fmt.Errorf("couldn't generate random number: %v", err)
		}
		sb.WriteByte(charset[i])
	}

	return sb.String(), nil
}

// generator returns a function that returns uniformly-random uint64s in the range [0, max).
func generator(max uint64) func() (uint64, error) {
	// Let N = math.MaxUint64+1. Our basic randomness primitive is to generate a random number
	// uniformly in the range [0, N). We want a number uniformly in the range [0, max). The first
	// question is if we can do this without rejection sampling: we can do without rejection
	// sampling iff N % max == 0. But since we can't compute with N (it's outside the range of
	// 64-bit numbers), we instead check if (N-1) % max == max - 1.

	if r := math.MaxUint64 % max; r == max-1 {
		// The desired range [0, max) divides evenly into natural range [0, N).
		// No need for rejection sampling, just use a modulus.
		return func() (uint64, error) {
			v, err := next()
			if err != nil {
				return 0, err
			}
			return v % max, nil
		}
	} else {
		// The desired range [0, max) does not divide evenly into natural range [0, N).
		// We must use rejection sampling. Our basic strategy is still to use a modulus, but reject
		// any samples from [0, N) that are in the final "partial" band of remainders to ensure
		// uniformity. There are N % max == r + 1 elements in the partial band, so we want to reject
		// any samples values that are greater than or equal to N - (N % max) == N - (r+1) ==
		// ~(r+1) + 1. (The final step in the previous equation is a standard bitwise identity:
		// for all X, N - X == ~X + 1.)
		lim := ^(r + 1) + 1
		return func() (uint64, error) {
			for {
				v, err := next()
				if err != nil {
					return 0, err
				}
				if v < lim {
					return v % max, nil
				}
			}
		}
	}
}

var (
	bufMu   sync.Mutex // bufMu protects fullBuf & buf
	fullBuf [4096]byte // size of fullBuf must be a multiple of 8
	buf     []byte
)

// next produces a uint64 value, chosen uniformly at random.
func next() (uint64, error) {
	bufMu.Lock()
	defer bufMu.Unlock()
	if len(buf) == 0 {
		if _, err := rand.Read(fullBuf[:]); err != nil {
			return 0, fmt.Errorf("couldn't read randomness: %v", err)
		}
		buf = fullBuf[:]
	}
	var v uint64
	v, buf = binary.BigEndian.Uint64(buf[:8]), buf[8:]
	return v, nil
}

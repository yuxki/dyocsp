package cache

import (
	"math/big"
	"sync"
	"time"

	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
)

// ResponseCacheStore uses a built-in map in Go to store
// ResponseCache instances. The store is primarily used by the OCSP responder application, which
// makes use of methods such as get, update, and truncate. However, it does not have
// explicit add or delete methods to modify individual items in the cache. Instead, it
// focuses on updating the entire cache as a whole, and includes functionality to update
// the cache's update time.
type ResponseCacheStore struct {
	cacheMap  map[string]ResponseCache
	now       date.Now
	UpdatedAt time.Time
	mu        sync.RWMutex
}

// NewResponseCacheStore creates and retruns new instance of ResponseCacheStore.
func NewResponseCacheStore() *ResponseCacheStore {
	cacheMap := make(map[string]ResponseCache, 0)
	updatedAt := date.NowGMT()
	return &ResponseCacheStore{
		cacheMap:  cacheMap,
		now:       date.NowGMT,
		UpdatedAt: updatedAt,
	}
}

func cacheMapKey(s *big.Int) (string, bool) {
	if s == nil {
		return "", false
	}
	return s.Text(db.SerialBase), true
}

// Update the response cache's override hashmap with the provided caches.
// Additionally, update the update date after the update is performed.
// This method returns nil when there are no duplicated serial numbers in the
// ocsp response and returns the duplicated serial numbers when they exist.
func (r *ResponseCacheStore) Update(caches []ResponseCache) []ResponseCache {
	defer func() {
		r.UpdatedAt = r.now()
	}()

	invalids := make([]ResponseCache, 0, len(caches))

	if caches == nil {
		r.cacheMap = make(map[string]ResponseCache, 0)
		return invalids
	}

	cacheMap := make(map[string]ResponseCache, len(caches))
	duplSet := make(map[string]struct{}, len(caches))

	for idx := range caches {
		// Check if it is possible to retrieve the serial number
		key, ok := cacheMapKey(caches[idx].Template().SerialNumber)
		if !ok {
			invalids = append(invalids, caches[idx])
			continue
		}

		// Check not dupulicated
		if _, ok := duplSet[key]; ok {
			invalids = append(invalids, caches[idx])
			continue
		}

		if _, ok := cacheMap[key]; ok {
			invalids = append(invalids, cacheMap[key])
			invalids = append(invalids, caches[idx])
			delete(cacheMap, key)
			duplSet[key] = struct{}{}
			continue
		}

		// Check if the OCSP response exists
		if res := caches[idx].Response(); res == nil {
			invalids = append(invalids, caches[idx])
			continue
		}

		cacheMap[key] = caches[idx]
	}

	r.mu.Lock()
	r.cacheMap = cacheMap
	r.mu.Unlock()

	return invalids
}

// Truncate resets/deletes all caches.
func (r *ResponseCacheStore) Truncate() error {
	r.Update(nil)
	return nil
}

// Get retrieves and returns the ocsp.ResponseCache
// with the provided serial number. If no cache is found matching the key,
// it returns an empty ocsp.ResponseCache and false.
func (r *ResponseCacheStore) Get(serialNumber *big.Int) (*ResponseCache, bool) {
	var cache ResponseCache

	// Check if it is possible to retrieve the serial number
	key, ok := cacheMapKey(serialNumber)
	if !ok {
		return nil, false
	}

	// Copy the cache map address for data protection
	// from replacing address by the updating cache job
	r.mu.RLock()
	cm := r.cacheMap
	r.mu.RUnlock()
	cache, ok = cm[key]
	if !ok {
		return nil, false
	}

	return &cache, true
}

// NewReadOnlyCacheStore creates and returns new ResponseCacheStoreRO instance.
// ResponseCacheStoreRO is a wrapper around the ResponseCacheStore object,
// providing only read APIs.
func (r *ResponseCacheStore) NewReadOnlyCacheStore() *ResponseCacheStoreRO {
	return &ResponseCacheStoreRO{cacheStore: r}
}

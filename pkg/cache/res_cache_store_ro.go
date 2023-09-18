package cache

import (
	"math/big"
)

// ResponseCacheStoreRO is read-only ResponseCacheStore.
// It should have only read method of the ResponseCacheStore.
type ResponseCacheStoreRO struct {
	cacheStore *ResponseCacheStore
}

// Get is a simple wrapper the Get method of the ResponseCacheStore.
func (r *ResponseCacheStoreRO) Get(serialNumber *big.Int) (*ResponseCache, bool) {
	return r.cacheStore.Get(serialNumber)
}

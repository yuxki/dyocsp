package cache

import (
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

func TestNewResponseCacheStore(t *testing.T) {
	t.Parallel()

	cacheStore := NewResponseCacheStore()
	now := date.NowGMT()
	if cacheStore.UpdatedAt.Compare(now) == 1 {
		t.Errorf("UpdateAt is later than Now(%#v): %#v", now, cacheStore.UpdatedAt)
	}
}

func TestResponseCacheStore_Update_Get_Delete(t *testing.T) {
	t.Parallel()

	serialGood := "72344BF34067BBA31EF44587CBFB16631332CD23"

	serialGoodNumber, _ := new(big.Int).SetString(serialGood, 16)

	entryGood := db.CertificateEntry{}
	entryGood.Ca = "sub-ca"
	entryGood.Serial = serialGoodNumber
	entryGood.RevType = "V"
	entryGood.ExpDate = time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC)
	entryGood.RevDate = time.Time{}
	entryGood.CRLReason = db.NotRevoked
	entryGood.Errors = map[db.InvalidWith]error{}

	tmplGood := ocsp.Response{}
	tmplGood.SerialNumber = serialGoodNumber
	tmplGood.Status = ocsp.Good
	tmplGood.ThisUpdate = time.Date(2023, 8, 9, 12, 30, 0, 0, time.UTC)
	tmplGood.RevokedAt = time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC)
	tmplGood.NextUpdate = time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC)

	resCacheGood := ResponseCache{
		entryGood,
		tmplGood,
		nil,
		nil,
	}
	_, err := resCacheGood.SetResponse([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	serialRevoked := "82344BF34067BBA31EF44587CBFB16631332CD23"
	serialRevokedNumber, _ := new(big.Int).SetString(serialRevoked, 16)

	entryRevoked := db.CertificateEntry{}
	entryRevoked.Ca = "sub-ca"
	entryRevoked.Serial = serialRevokedNumber
	entryRevoked.RevType = "R"
	entryRevoked.ExpDate = time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC)
	entryRevoked.RevDate = time.Date(2023, 8, 9, 12, 33, 17, 0, time.UTC)
	entryRevoked.CRLReason = ocsp.Unspecified
	entryRevoked.Errors = map[db.InvalidWith]error{}

	tmplRevoked := ocsp.Response{}
	tmplRevoked.SerialNumber = serialRevokedNumber
	tmplRevoked.Status = ocsp.Revoked
	tmplRevoked.ThisUpdate = time.Date(2023, 8, 9, 12, 40, 0, 0, time.UTC)
	tmplRevoked.RevokedAt = time.Date(2023, 8, 9, 12, 33, 17, 0, time.UTC)
	tmplRevoked.NextUpdate = time.Date(2023, 8, 9, 22, 40, 0, 0, time.UTC)

	serialGetNumber := serialGoodNumber

	resCacheRevoked := ResponseCache{
		entryRevoked,
		tmplRevoked,
		nil,
		nil,
	}
	_, err = resCacheRevoked.SetResponse([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	data := []struct {
		testCase string
		// test data
		caches []ResponseCache
		// want
		invalidCaches []ResponseCache
		gotCache      *ResponseCache
		errMsg        string
	}{
		{
			"All caches are valid.",
			[]ResponseCache{
				resCacheGood,
				resCacheRevoked,
			},
			[]ResponseCache{},
			&resCacheGood,
			"",
		},
		{
			"There is a invalid cache: no signed response cache.",
			[]ResponseCache{
				resCacheGood,
				{
					entryRevoked,
					tmplRevoked,
					nil,
					nil,
				},
			},
			[]ResponseCache{
				{
					entryRevoked,
					tmplRevoked,
					nil,
					nil,
				},
			},
			&resCacheGood,
			"",
		},
		{
			"There is a invalid cache: no serial number.",
			[]ResponseCache{
				resCacheGood,
				{
					entryRevoked,
					ocsp.Response{},
					[]byte("abcdefg"),
					nil,
				},
			},
			[]ResponseCache{
				{
					entryRevoked,
					ocsp.Response{},
					[]byte("abcdefg"),
					nil,
				},
			},
			&resCacheGood,
			"",
		},
		{
			"Dupulicated serial.",
			[]ResponseCache{
				resCacheGood,
				resCacheRevoked,
				resCacheRevoked,
			},
			[]ResponseCache{
				resCacheRevoked,
				resCacheRevoked,
			},
			&resCacheGood,
			"",
		},
		{
			"There is no cache.",
			nil,
			[]ResponseCache{},
			nil,
			"",
		},
	}
	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			cacheStore := NewResponseCacheStore()

			// Check getting from initial store
			_, ok := cacheStore.Get(serialGetNumber)
			if ok {
				t.Fatalf("Initial CacheStore returns false as ok but got: %#v", ok)
			}

			preAtUpdate := cacheStore.UpdatedAt
			cacheStore.now = func() time.Time { return time.Date(2033, 8, 9, 12, 30, 0, 0, time.UTC) }

			// Update cache store
			invalds := cacheStore.Update(d.caches)
			if !reflect.DeepEqual(invalds, d.invalidCaches) {
				t.Errorf("Expected invalid caches are %#v but: %#v", d.invalidCaches, invalds)
			}
			if preAtUpdate.Compare(cacheStore.UpdatedAt) == 1 {
				t.Errorf("UpdateAt is later than previous updation(%#v): %#v", preAtUpdate, cacheStore.UpdatedAt)
			}

			cacheStore.now = func() time.Time { return time.Date(2033, 8, 9, 12, 30, 1, 0, time.UTC) }

			// Get a cache from cache store
			gotCache, ok := cacheStore.Get(serialGetNumber)
			if !ok {
				if gotCache != nil {
					t.Errorf("Expected got cache is empyt but: %#v", gotCache)
				}
				return
			}
			if !reflect.DeepEqual(gotCache, d.gotCache) {
				t.Errorf("Expected got cache is %#v but: %#v", d.gotCache, gotCache)
			}

			preAtUpdate = cacheStore.UpdatedAt
			cacheStore.now = func() time.Time { return time.Date(2033, 8, 9, 12, 30, 2, 0, time.UTC) }

			// Truncate cache store
			_ = cacheStore.Truncate()
			if preAtUpdate.Compare(cacheStore.UpdatedAt) == 1 {
				t.Errorf("UpdateAt is later than previous updation(%#v): %#v", preAtUpdate, cacheStore.UpdatedAt)
			}
			gotCache, ok = cacheStore.Get(serialGetNumber)
			if ok {
				t.Errorf("Expected got cache is empyt but: %#v", gotCache)
			}
		})
	}
}

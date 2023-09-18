package dyocsp

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/db"
	"github.com/rs/zerolog/log"
)

type StubCADBClient struct {
	caName string
	db     []db.IntermidiateEntry
}

func (s StubCADBClient) Scan(ctx context.Context) ([]db.IntermidiateEntry, error) {
	return s.db, nil
}

func testGetCache(t *testing.T, targetSerial string, store *cache.ResponseCacheStore) *cache.ResponseCache {
	t.Helper()

	serial := new(big.Int)
	serial, ok := serial.SetString(targetSerial, db.SerialBase)
	if !ok {
		t.Fatal("String could not be *big.Int.")
	}

	cache, ok := store.Get(serial)
	if !ok {
		t.Fatal("Cache could not be found.")
	}

	return cache
}

func TestCacheBatch_Run_DBNotChanged(t *testing.T) {
	t.Parallel()

	targetSerialStr := "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5"
	targetSerial, ok := new(big.Int).SetString(targetSerialStr, db.SerialBase)
	if !ok {
		t.Fatal("String could not be *big.Int.")
	}

	fileDB := []db.IntermidiateEntry{
		{
			Ca:        "test-ca",
			Serial:    targetSerialStr,
			RevType:   "V",
			ExpDate:   "230925234911Z",
			RevDate:   "",
			CRLReason: "",
		},
		{
			Ca:        "test-ca",
			Serial:    "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F9",
			RevType:   "E",
			ExpDate:   "19000914235323Z",
			RevDate:   "",
			CRLReason: "",
		},

		{
			Ca:        "test-ca",
			Serial:    "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F7",
			RevType:   "R",
			ExpDate:   "330823234911Z",
			RevDate:   "230826234911Z",
			CRLReason: "unspecified",
		},
	}
	client := StubCADBClient{"test-ca", fileDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	spec := CacheBatchSpec{
		Interval: time.Second * 1,
		Delay:    time.Second * 0,
		Logger:   log.Logger,
		Strict:   false,
	}
	batch := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		time.Now().UTC(),
		spec,
	)

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.GetEntry().Serial.Cmp(targetSerial) != 0 {
		t.Fatalf("Expected serial is %s but got %s.",
			cache.GetEntry().Serial.Text(db.SerialBase),
			cache.GetEntry().Serial.Text(db.SerialBase))
	}
}

func TestCacheBatch_Run_DBChanged(t *testing.T) {
	t.Parallel()

	targetSerial := "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5"
	wantType := "R"

	currentDB := []db.IntermidiateEntry{
		{
			Ca:        "test-ca",
			Serial:    targetSerial,
			RevType:   "V",
			ExpDate:   "230925234911Z",
			RevDate:   "",
			CRLReason: "",
		},
	}
	client := StubCADBClient{"test-ca", currentDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	spec := CacheBatchSpec{
		Interval: time.Second * 1,
		Delay:    time.Second * 0,
		Logger:   log.Logger,
		Strict:   false,
	}
	batch := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		time.Now().UTC(),
		spec,
	)

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)
	// Do first

	// Update DB &Interval
	currentDB[0].RevType = wantType
	currentDB[0].RevDate = "230826234911Z"
	currentDB[0].CRLReason = "unspecified"
	time.Sleep(time.Second * 2)

	// Do Second

	// Do Assertion
	cache := testGetCache(t, targetSerial, store)

	if string(cache.GetEntry().RevType) != wantType {
		t.Fatalf("Expected rev type is %s but got %s.", wantType, string(cache.GetEntry().RevType))
	}
}

func TestCacheBatch_Run_DelegatedResponder(t *testing.T) {
	t.Parallel()

	targetSerialStr := "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5"

	fileDB := []db.IntermidiateEntry{
		{
			Ca:        "test-ca",
			Serial:    targetSerialStr,
			RevType:   "V",
			ExpDate:   "230925234911Z",
			RevDate:   "",
			CRLReason: "",
		},
	}
	client := StubCADBClient{"test-ca", fileDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	spec := CacheBatchSpec{
		Interval: time.Second * 1,
		Delay:    time.Second * 0,
		Logger:   log.Logger,
		Strict:   false,
	}
	batch := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		time.Now().UTC(),
		spec,
	)

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.GetTemplate().Certificate == nil {
		t.Fatal("Delegated signing responder may contain itself certificate.")
	}
}

func TestCacheBatch_Run_DirectResponder(t *testing.T) {
	t.Parallel()

	targetSerialStr := "8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5"

	fileDB := []db.IntermidiateEntry{
		{
			Ca:        "test-ca",
			Serial:    targetSerialStr,
			RevType:   "V",
			ExpDate:   "230925234911Z",
			RevDate:   "",
			CRLReason: "",
		},
	}
	client := StubCADBClient{"test-ca", fileDB}
	responder := testCreateDirectResponder(t)
	store := cache.NewResponseCacheStore()
	spec := CacheBatchSpec{
		Interval: time.Second * 1,
		Delay:    time.Second * 0,
		Logger:   log.Logger,
		Strict:   false,
	}
	batch := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		time.Now().UTC(),
		spec,
	)

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.GetTemplate().Certificate != nil {
		t.Fatalf("Direct signing responder may not contain itself certificate.")
	}
}

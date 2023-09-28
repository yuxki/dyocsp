package dyocsp

import (
	"context"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
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

func TestNewCacheBatch_OptoinsDefaults(t *testing.T) {
	t.Parallel()

	currentDB := []db.IntermidiateEntry{}
	client := StubCADBClient{"test-ca", currentDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	batch, err := NewCacheBatch("test-ca", store, client, responder, date.NowGMT())
	if err != nil {
		t.Fatal(err)
	}

	if batch.interval != time.Second*DefaultInterval {
		t.Error("value of interval is not default.")
	}
	if batch.delay != 0 {
		t.Error("value of delay is not default.")
	}
	if batch.strict != false {
		t.Error("value of strict is not default.")
	}
	if batch.expiration != Ignore {
		t.Error("value of expiration is not default.")
	}
	if batch.logger != &log.Logger {
		t.Error("value of logger is not default.")
	}
	if batch.quite != nil {
		t.Error("value of quite is not default.")
	}
}

func TestNewCacheBatch_OptoinsSet(t *testing.T) {
	t.Parallel()

	currentDB := []db.IntermidiateEntry{}
	client := StubCADBClient{"test-ca", currentDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	logger := zerolog.New(os.Stdout).With().Logger()
	ch := make(chan string)
	batch, err := NewCacheBatch("test-ca", store, client, responder, date.NowGMT(),
		WithIntervalSec(10), WithDelay(time.Second*5), WithStrict(true), WithExpiration(Warn), WithLogger(&logger), WithQuiteChan(ch))
	if err != nil {
		t.Fatal(err)
	}

	if batch.interval != time.Second*10 {
		t.Error("value of interval is not specified.")
	}
	if batch.delay != time.Second*5 {
		t.Error("value of delay is not specified.")
	}
	if batch.strict != true {
		t.Error("value of strict is not specified.")
	}
	if batch.expiration != Warn {
		t.Error("value of expiration is not specified.")
	}
	if batch.logger != &logger {
		t.Error("value of logger is not specified.")
	}
	if batch.quite == nil {
		t.Error("value of quite is not specified.")
	}
}

func TestNewCacheBatch_ErrDelayExceedsInterval(t *testing.T) {
	t.Parallel()

	currentDB := []db.IntermidiateEntry{}
	client := StubCADBClient{"test-ca", currentDB}
	responder := testCreateDelegatedResponder(t)
	store := cache.NewResponseCacheStore()
	_, err := NewCacheBatch("test-ca", store, client, responder, date.NowGMT(),
		WithIntervalSec(1), WithDelay(time.Second*5))
	if err == nil {
		t.Fatal("expected non-nil error.")
	}
	if errors.Is(err, ErrDelayExceedsInterval) {
		t.Fatal("unexpected error returned.")
	}
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
	batch, err := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		date.NowGMT(),
		WithIntervalSec(1),
		WithDelay(0),
		WithStrict(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.Entry().Serial.Cmp(targetSerial) != 0 {
		t.Fatalf("Expected serial is %s but got %s.",
			cache.Entry().Serial.Text(db.SerialBase),
			cache.Entry().Serial.Text(db.SerialBase))
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
	batch, err := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		date.NowGMT(),
		WithIntervalSec(1),
		WithDelay(0),
		WithStrict(false),
	)
	if err != nil {
		t.Fatal(err)
	}

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

	if string(cache.Entry().RevType) != wantType {
		t.Fatalf("Expected rev type is %s but got %s.", wantType, string(cache.Entry().RevType))
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
	batch, err := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		date.NowGMT(),
		WithIntervalSec(1),
		WithDelay(0),
		WithStrict(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.Template().Certificate == nil {
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
	batch, err := NewCacheBatch(
		"test-ca",
		store,
		client,
		responder,
		date.NowGMT(),
		WithIntervalSec(1),
		WithDelay(0),
		WithStrict(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	go batch.Run(context.TODO())
	time.Sleep(time.Second * 1)

	cache := testGetCache(t, targetSerialStr, store)

	if cache.Template().Certificate != nil {
		t.Fatalf("Direct signing responder may not contain itself certificate.")
	}
}

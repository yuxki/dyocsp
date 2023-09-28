package dyocsp

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
)

type expirationLogger struct {
	Logger zerolog.Logger
}

func (e *expirationLogger) InvalidMsg(serial string, msg string) {
	e.Logger.Warn().Msg(fmt.Sprintf("%s: %s", msg, serial))
}

func (e *expirationLogger) WarnMsg(serial *big.Int, msg string) {
	e.Logger.Warn().Msg(fmt.Sprintf("%s: %s", msg, serial.Text(db.SerialBase)))
}

// CADBClient is an interface that represents a client for scanning a database
// and creating IntermediateEntries.
type CADBClient interface {
	Scan(ctx context.Context) ([]db.IntermidiateEntry, error)
}

func createExpirationLogger(expiration expBehavior, logger zerolog.Logger) *db.ExpirationControl {
	expLogger := expirationLogger{Logger: logger}
	var expCtl *db.ExpirationControl
	switch expiration {
	case Warn:
		expCtl = db.NewExpirationControl(db.WithWarnOnExpiration(), db.WithLogger(&expLogger))
	case Invalid:
		expCtl = db.NewExpirationControl()
	}

	return expCtl
}

// The CacheBatch function scans the CA database for certificates with revocation
// information and generates response caches. It then updates the dyocsp.ResponseCacheStore
// with these caches. The job is repeated infinitely with an interval between each job. The
// interval refers to the interval of the OCSP Response Next Update. This Loop delays processing
// until the specified interval is reached, taking into account the duration of the batch job.
type CacheBatch struct {
	ca          string
	cacheStore  *cache.ResponseCacheStore
	caDBClient  CADBClient
	responder   *Responder
	now         date.Now
	nextUpdate  time.Time
	batchSerial int
	interval    time.Duration
	// Options
	intervalSec int
	delay       time.Duration
	strict      bool
	expiration  expBehavior
	quite       chan string
	logger      *zerolog.Logger
}

// Default values.
const (
	DefaultInterval = 60
)

type expBehavior int

const (
	Ignore expBehavior = iota
	Warn
	Invalid
)

var ErrDelayExceedsInterval = errors.New("delay must be less than interval or equal")

// CacheBatchOption is type of an functional option for dyocsp.CacheBatch.
type CacheBatchOption func(*CacheBatch)

// WithIntervalSec sets interval seconds option. Interval is the duration specification
// between the Next Update and the Next Update. If 0 or less than 0 is set, DefaultInterval
// is used.
func WithIntervalSec(sec int) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.intervalSec = sec
	}
}

// WithDelay sets delay option. Delay is a duration specification that pauses
// the execution of the program for a specified CacheBatchSpec.Interval before
// continuing to process further. Default value is 0 and. If value is less than 0,
// default value is used.
func WithDelay(delay time.Duration) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.delay = delay
	}
}

// WithDelay sets  strict option.// The strict specification of dyocsp.CacheBatch
// means that it is in 'strict mode',which calls panic() when a CADBClient error
// occurs during the scanning of the database. Default value is false.
func WithStrict(strict bool) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.strict = strict
	}
}

// WithExpiration sets expiration. This expiration determines the behavior when the
// Expiration Date is exceeded. Default value is Ignore.
func WithExpiration(exp expBehavior) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.expiration = exp
	}
}

// WithLogger sets logger. If not set, global logger is used.
func WithLogger(logger *zerolog.Logger) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.logger = logger
	}
}

// WithQuietChan sets a quiet message channel, which
// stops the loop of dyocsp.CacheBatch.Run(). It also sends a message immediately
// before quieting the loop.
func WithQuiteChan(quite chan string) func(*CacheBatch) {
	return func(c *CacheBatch) {
		c.quite = quite
	}
}

// NewCacheBatch creates a new instance of dyocsp.CacheBatch and returns it.
func NewCacheBatch(
	ca string,
	cacheStore *cache.ResponseCacheStore,
	caDBClient CADBClient,
	responder *Responder,
	nextUpdate time.Time,
	opts ...CacheBatchOption,
) (*CacheBatch, error) {
	batch := &CacheBatch{
		ca:          ca,
		cacheStore:  cacheStore,
		caDBClient:  caDBClient,
		responder:   responder,
		now:         date.NowGMT,
		nextUpdate:  nextUpdate,
		batchSerial: 0,
	}

	for _, opt := range opts {
		opt(batch)
	}

	if batch.intervalSec <= 0 {
		batch.interval = time.Second * DefaultInterval
	} else {
		batch.interval = time.Second * time.Duration(batch.intervalSec)
	}

	if batch.delay < 0 {
		batch.delay = 0
	}

	if batch.delay > batch.interval {
		return nil, ErrDelayExceedsInterval
	}

	if batch.logger == nil {
		batch.logger = &log.Logger
	}

	return batch, nil
}

func (c *CacheBatch) logEntryErrors(ce db.CertificateEntry, logger *zerolog.Logger) (noError bool) {
	noError = true
	for i := db.MalformSerial; i <= db.UndefinedCRLReason; i++ {
		err, ok := ce.Errors[i]
		if !ok {
			continue
		}
		logger.Error().Err(err).Msg("")
		noError = false
	}
	return noError
}

// RunOnce returns a slice of cache.ResponseCache through the following process.
//   - Scan the CA database to identify entries related to certificate revocation.
//   - Verify and parse entries for pre-signed response caches.
//   - Sign the pre-signed response caches using the dyocsp.Responder.
//
// This function is the main job of dyocsp.CacheBatch.Run().
func (c *CacheBatch) RunOnce(ctx context.Context) []cache.ResponseCache {
	logger := zerolog.Ctx(ctx)

	// DB --> IntermidiateEntry
	var itmds []db.IntermidiateEntry
	logger.Info().Msg("Database scan started by client.")
	itmds, err := c.caDBClient.Scan(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("")
		if c.strict {
			panic(err)
		}
	}
	logger.Info().Msg("Database scan completed.")
	logger.Debug().Msgf("List of scanned entries from the database: %v", itmds)

	// IntermidiateEntry --> CertificateEntry
	expCtl := createExpirationLogger(c.expiration, *logger)
	exch := db.NewEntryExchange()
	entries := make([]db.CertificateEntry, 0, len(itmds))
	for _, itmd := range itmds {
		// When certificate is expired, response cache is not created.
		if itmd.RevType == "E" {
			continue
		}

		ce := exch.ParseCertificateEntry(itmd)
		if noerr := c.logEntryErrors(ce, logger); noerr {
			entries = append(entries, ce)
		}

		if expCtl != nil {
			// When certificate after date is past, response cache is not created.
			entries = expCtl.Do(c.now(), entries)
		}
	}
	logger.Debug().Msgf("List of exchange entries from scanned entries: %v", entries)

	// CertificateEntry --> cache.ResponseCache(Pre-Signed)
	resCaches := make([]cache.ResponseCache, 0, len(entries))
	for _, entry := range entries {
		resCache, err := cache.CreatePreSignedResponseCache(entry, c.nextUpdate, c.interval)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		if c.responder.AuthType == Delegation {
			resCache.SetCertToTemplate(c.responder.rCert)
		}
		resCaches = append(resCaches, resCache)
	}
	logger.Debug().Msgf("Number of pre-signed-caches: %d", len(resCaches))

	// cache.ResponseCache(Pre-Signed) --> cache.ResponseCache(Signed)
	signedCaches := make([]cache.ResponseCache, 0, len(resCaches))
	for _, rc := range resCaches {
		signedCache, err := c.responder.SignCacheResponse(rc)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to sign :%v", rc))
		} else {
			signedCaches = append(signedCaches, signedCache)
		}
	}
	logger.Debug().Msgf("Number of signed-caches: %d", len(signedCaches))

	return signedCaches
}

func (c *CacheBatch) syncWithWaitDuration(now time.Time) time.Duration {
	waitDur := c.interval
	switch r := now.Compare(c.nextUpdate); r {
	case -1:
		waitDur = (waitDur + c.nextUpdate.Sub(now)) - c.delay
	case 1:
		waitDur = (waitDur - now.Sub(c.nextUpdate)) - c.delay
		if waitDur < 0 {
			waitDur = 0
		}
	default:
		waitDur -= c.delay
	}

	return waitDur
}

func (c *CacheBatch) logBatchSummary(ctx context.Context, start time.Time) {
	logger := zerolog.Ctx(ctx)

	dur := fmt.Sprintf("%v", time.Since(start))
	logger.Info().
		Str("duration", dur).
		Msg("Cache generation batch completed.")
}

func (c *CacheBatch) waitForNextUpdate(ctx context.Context, waitDur time.Duration) {
	logger := zerolog.Ctx(ctx)

	logger.Info().Dur("wait", waitDur).
		Time("next-update", c.nextUpdate).
		Msg("Waiting for the next update.")

	if c.quite != nil {
	outer:
		for {
			select {
			case <-time.After(waitDur):
				break outer
			case msg := <-c.quite:
				// Stop when it received quite message
				logger.Info().Msgf("Quite message received, stop loop: %s", msg)
				c.quite <- "Loop stopped."
				return
			}
		}
	} else {
		time.Sleep(waitDur)
	}
}

// Run starts a loop that processes the batch and caches signed response
// caches in the interval specification.
// The batch execute following jobs in order.
//   - Scan the CA database with db.CADBClient.Scan().
//   - Verify revocation information entries and create, sign OCSP response.
//   - Verify the revocation information entries.
//   - Create and sign an OCSP response.
//   - Compute the wait time needed to adjust for any out-of-sync between the
//     actual time and the next update time. This can occur due to delays in processing
//     or the duration of batch processing.
//   - Update Next Update.
//   - Wait for next update.
func (c *CacheBatch) Run(ctx context.Context) {
	for {
		startTime := c.now()

		logger := c.logger.With().Int("batch_serial", c.batchSerial).Logger()
		logger.Info().Msg("Starting cache generation batch.")
		ctx := logger.WithContext(ctx)

		// Create response caches
		caches := c.RunOnce(ctx)

		// Update cache store
		invs := c.cacheStore.Update(caches)
		for _, inv := range invs {
			logger.Error().Msgf("Invalid response cache: %s", inv.Entry().Serial)
		}
		logger.Info().Msg("Response cache updated.")

		// Summury of this loop batch
		c.logBatchSummary(ctx, startTime)

		waitDur := c.syncWithWaitDuration(c.now())

		// Update nextUpdate
		c.nextUpdate = c.nextUpdate.Add(c.interval)

		// Wait for next update
		c.waitForNextUpdate(ctx, waitDur)

		c.batchSerial++
	}
}

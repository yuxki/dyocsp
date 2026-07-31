package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/justinas/alice"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/yuxki/dyocsp"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/config"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
	"gopkg.in/yaml.v3"
)

func newResponder(cfg config.DyOCSPConfig) *dyocsp.Responder {
	certPem, err := os.ReadFile(cfg.Certificate)
	if err != nil {
		stdlog.Fatalf("error:responder certificate: %v", err)
	}

	var keyPem []byte
	keyPem = []byte(os.Getenv("DYOCSP_PRIVATE_KEY"))
	if cfg.Key != "" {
		if len(keyPem) > 0 {
			stdlog.Fatal(
				"error:DYOCSP_PRIVATE_KEY and .responder.responder_key are exclusive.",
			)
		}

		keyPem, err = os.ReadFile(cfg.Key)
		if err != nil {
			stdlog.Fatalf("error:responder key: %v", err)
		}
	}

	issuerCertPem, err := os.ReadFile(cfg.Issuer)
	if err != nil {
		stdlog.Fatalf("error:issuer certificate: %v", err)
	}

	responder, err := dyocsp.BuildResponder(certPem, keyPem, issuerCertPem, date.NowGMT())
	if err != nil {
		stdlog.Fatal(err.Error())
	}

	return responder
}

var ErrFileDBInvalid = errors.New("invalid db file")

func newFileDBClient(cfg config.DyOCSPConfig) (db.FileDBClient, error) {
	var dbClient db.FileDBClient

	abs, err := filepath.Abs(cfg.FileDBFile)
	if err != nil {
		return dbClient, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return dbClient, err
	}
	if info.IsDir() {
		return dbClient, ErrFileDBInvalid
	}

	return db.NewFileDBClient(cfg.CA, cfg.FileDBFile), nil
}

func newDynamoDBClient(ctx context.Context, cfg config.DyOCSPConfig) (db.DynamoDBClient, error) {
	ca := cfg.CA
	caTable := cfg.DynamoDBTableName
	caGsi := cfg.DynamoDBCAGsi

	aCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.DynamoDBRegion),
		awsconfig.WithRetryMaxAttempts(cfg.DynamoDBRetryMaxAttempts),
	)
	if err != nil {
		var dynamoDBClient db.DynamoDBClient
		return dynamoDBClient, err
	}

	var client *dynamodb.Client
	if cfg.DynamoDBEndpoint == "" {
		client = dynamodb.NewFromConfig(aCfg)
	} else {
		client = dynamodb.NewFromConfig(aCfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = &cfg.DynamoDBEndpoint
		})
	}

	return db.NewDynamoDBClient(client, &ca, &caTable, &caGsi, cfg.DynamoDBTimeout), nil
}

const (
	cacheBatchRole   = "cache-generation"
	CacheHandlerRole = "handle-ocsp-request"
)

func chainHTTPAccessHandler(c alice.Chain) alice.Chain {
	chain := c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))
	chain = chain.Append(hlog.RemoteAddrHandler("ip"))
	chain = chain.Append(hlog.UserAgentHandler("user_agent"))
	return chain
}

const shutdownTimeout = 10 * time.Second

func run(ctx context.Context, cfg config.DyOCSPConfig, responder *dyocsp.Responder) error {
	setupLogger(cfg)

	rootCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create DB client
	var dbClient dyocsp.CADBClient
	var err error

	switch cfg.DBType {
	case config.FileDBType:
		dbClient, err = newFileDBClient(cfg)
	case config.DynamoDBType:
		dbClient, err = newDynamoDBClient(ctx, cfg)
	default:
		err = config.MissingParameterError{Param: "db.<db-type>"}
	}
	if err != nil {
		return err
	}

	// Create cache store
	cacheStore := cache.NewResponseCacheStore()

	// Create CacheBatch
	blogger := log.Logger.With().Str("role", cacheBatchRole).Logger()
	batch, err := dyocsp.NewCacheBatch(
		cfg.CA,
		cacheStore,
		dbClient,
		responder,
		date.NowGMT(),
		// bSpec,
		dyocsp.WithIntervalSec(cfg.Interval),
		dyocsp.WithDelay(time.Second*time.Duration(cfg.Delay)),
		dyocsp.WithStrict(cfg.Strict),
		dyocsp.WithLogger(&blogger),
	)
	if err != nil {
		return err
	}

	// Run batch generating caches
	batchDone := make(chan struct{})
	go func() {
		defer close(batchDone)
		batch.Run(rootCtx)
	}()

	// Create Server
	hLogger := log.Logger.With().Str("role", CacheHandlerRole).Logger()
	cacheStoreRO := cacheStore.NewReadOnlyCacheStore()

	chain := alice.New()
	chain = chain.Append(hlog.NewHandler(hLogger))
	chain = chainHTTPAccessHandler(chain)
	cacheHander := dyocsp.NewCacheHandler(
		cacheStoreRO,
		responder,
		chain,
		dyocsp.WithMaxAge(cfg.CacheControlMaxAge),
		dyocsp.WithMaxRequestBytes(cfg.MaxRequestBytes),
		dyocsp.WithHandlerLogger(&hLogger),
	)

	host := net.JoinHostPort(cfg.Domain, cfg.Port)
	server := dyocsp.CreateHTTPServer(
		host,
		cfg,
		cacheHander,
	)

	serverError := make(chan error, 1)
	go func() {
		serverError <- server.ListenAndServe()
	}()

	select {
	case err = <-serverError:
		cancel()
		<-batchDone
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("listening server: %w", err)
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer shutdownCancel()

		shutdownErr := server.Shutdown(shutdownCtx)
		cancel()
		<-batchDone
		if shutdownErr != nil {
			return fmt.Errorf("shutting down server: %w", shutdownErr)
		}
		return nil
	}
}

func main() {
	cfgPtr := flag.String("c", "", "The path of configuration.")
	validatePtr := flag.Bool(
		"validate",
		false,
		"Only validate the configuration when that has error, exit with 1, and not exit with 0.",
	)
	flag.Parse()

	if *cfgPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	cfgF, err := os.Open(*cfgPtr)
	if err != nil {
		stdlog.Fatal(err)
	}

	var cfgYml config.ConfigYAML
	err = yaml.NewDecoder(cfgF).Decode(&cfgYml)
	if err != nil {
		stdlog.Fatal(err)
	}

	var cfg config.DyOCSPConfig
	cfg, errs := cfgYml.Verify(cfg)
	if errs != nil {
		for _, err := range errs {
			stdlog.Print(err)
		}
		os.Exit(1)
	}

	if *validatePtr {
		stdlog.Print("Validition Success.")
		os.Exit(0)
	}

	if err := cfgF.Close(); err != nil {
		stdlog.Printf("failed to close file: %v\n", err)
	}

	responder := newResponder(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = run(ctx, cfg, responder)
	if err != nil {
		stdlog.Fatal(err)
	}
}

package main

import (
	"context"
	"errors"
	"flag"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

func newFileDBClient(cfg config.DyOCSPConfig) db.FileDBClient {
	abs, err := filepath.Abs(cfg.FileDBFile)
	if err != nil {
		stdlog.Fatal(err.Error())
	}
	info, err := os.Stat(abs)
	if err != nil {
		stdlog.Fatal(err.Error())
	}
	if info.IsDir() {
		stdlog.Fatalf("%s is not a file.", abs)
	}

	return db.NewFileDBClient(cfg.CA, cfg.FileDBFile)
}

func newDynamoDBClient(cfg config.DyOCSPConfig) db.DynamoDBClient {
	ca := cfg.CA
	caTable := cfg.DynamoDBTableName
	caGsi := cfg.DynamoDBCAGsi

	aCfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(cfg.DynamoDBRegion),
		awsconfig.WithRetryMaxAttempts(cfg.DynamoDBRetryMaxAttempts),
	)
	if err != nil {
		panic(err)
	}

	var client *dynamodb.Client
	if cfg.DynamoDBEndpoint == "" {
		client = dynamodb.NewFromConfig(aCfg)
	} else {
		client = dynamodb.NewFromConfig(aCfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = &cfg.DynamoDBEndpoint
		})
	}

	return db.NewDynamoDBClient(client, &ca, &caTable, &caGsi, cfg.DynamoDBTimeout)
}

func newCADBClientFromConfig(cfg config.DyOCSPConfig) (db.CADBClient, error) {
	switch cfg.DBType {
	case config.FileDBType:
		return newFileDBClient(cfg), nil
	case config.DynamoDBType:
		return newDynamoDBClient(cfg), nil
	}

	err := config.MissingParameterError{}
	err.Param = "db.<db-type>"

	return nil, err
}

func printUsage() {
	stdlog.Println("Usage: dyocsp -c CONFIG_FILE")
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

func run(cfg config.DyOCSPConfig, responder *dyocsp.Responder) {
	setupLogger(cfg)

	rootCtx := context.Background()
	rootCtx, cancel := context.WithCancel(rootCtx)
	defer cancel()

	// Create DB client
	dbClient, err := newCADBClientFromConfig(cfg)
	if err != nil {
		panic(err)
	}

	// Create cache store
	cacheStore := cache.NewResponseCacheStore()

	// Create CacheBatch
	quite := make(chan string)

	bSpec := dyocsp.CacheBatchSpec{
		Interval: time.Second * time.Duration(cfg.Interval),
		Delay:    time.Second * time.Duration(cfg.Delay),
		Logger:   log.Logger.With().Str("role", cacheBatchRole).Logger(),
		Strict:   cfg.Strict,
	}
	batch := dyocsp.NewCacheBatch(
		cfg.CA,
		cacheStore,
		dbClient,
		responder,
		date.NowGMT(),
		bSpec,
		dyocsp.WithQuiteChan(quite),
	)

	// Run batch generating caches
	go batch.Run(rootCtx)

	// Create Server
	hLogger := log.Logger.With().Str("role", CacheHandlerRole).Logger()
	hSpec := dyocsp.CacheHandlerSpec{
		MaxRequestBytes: cfg.MaxRequestBytes,
		MaxAge:          cfg.CacheControlMaxAge,
		Logger:          hLogger,
	}

	cacheStoreRO := cacheStore.NewReadOnlyCacheStore()

	chain := alice.New()
	chain = chain.Append(hlog.NewHandler(hLogger))
	chain = chainHTTPAccessHandler(chain)
	cacheHander := dyocsp.NewCacheHandler(cacheStoreRO, responder, hSpec, chain)

	host := net.JoinHostPort(cfg.Domain, cfg.Port)
	server := dyocsp.CreateHTTPServer(
		host,
		cfg,
		cacheHander,
	)

	// Run Server
	err = server.ListenAndServe()
	if err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		cancel()
		quite <- "Quite on error"
		stdlog.Printf("Batch loop quited: received message from caching batch: %s", <-quite)
		stdlog.Fatalf("error:listening server: %v", err)
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
		printUsage()
		os.Exit(1)
	}

	cfgF, err := os.Open(*cfgPtr)
	if err != nil {
		stdlog.Fatalf("error:cfg file: %v", err)
		os.Exit(1)
	}

	var cfgYml config.ConfigYAML
	err = yaml.NewDecoder(cfgF).Decode(&cfgYml)
	if err != nil {
		stdlog.Fatalf("error:cfg file: %v", err)
		os.Exit(1)
	}

	var cfg config.DyOCSPConfig
	cfg, errs := cfgYml.Verify(cfg)
	if errs != nil {
		for _, err := range errs {
			stdlog.Printf("error:cfg file: %v", err)
		}
		os.Exit(1)
	}

	if *validatePtr {
		stdlog.Print("Validition Success.")
		os.Exit(0)
	}

	responder := newResponder(cfg)

	run(cfg, responder)
}

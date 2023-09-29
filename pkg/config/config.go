package config

import (
	"fmt"
	"regexp"

	"github.com/rs/zerolog"
)

// The DyOCSPConfig struct contains configuration members for creating instances
// of DyOCSP. Please refer to the documentation for detailed information about each
// configuration.
type DyOCSPConfig struct {
	// From ConfigYAML
	Version                  string
	Strict                   bool
	Expiration               string
	LogLevel                 string
	LogFormat                string
	CA                       string
	Certificate              string
	Key                      string
	Issuer                   string
	Interval                 int
	Delay                    int
	DynamoDBRegion           string
	DynamoDBTableName        string
	DynamoDBCAGsi            string
	DynamoDBEndpoint         string
	DynamoDBRetryMaxAttempts int
	DynamoDBTimeout          int
	FileDBFile               string
	Port                     string
	Domain                   string
	ReadTimeout              int
	WriteTimeout             int
	ReadHeaderTimeout        int
	MaxHeaderBytes           int
	MaxRequestBytes          int
	CacheControlMaxAge       int
	// From this struct
	ZerologLevel  zerolog.Level
	ZerologFormat LogFormat
	DBType        CADBType
}

// The ConfigYAML is a configuration file in YAML format.
// To indicate a non-specified status, the member of type int should be a pointer.
// This struct instance verifies the instance's own members and creates a DyOCSPConfig
// object based on the instance's attributes.
type ConfigYAML struct {
	Version    string `yaml:"version"`
	Strict     bool   `yaml:"strict"`
	Expiration string `yaml:"expiration"`
	Log        struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
	Responder struct {
		CA          string `yaml:"ca"`
		Certificate string `yaml:"responder_certificate"`
		Key         string `yaml:"responder_key"`
		Issuer      string `yaml:"issuer_certificate"`
	} `yaml:"responder"`
	Cache struct {
		Interval *int `yaml:"interval"`
		Delay    *int `yaml:"delay"`
	} `yaml:"cache"`
	DB struct {
		DynamoDB *struct {
			Region           string `yaml:"region"`
			TableName        string `yaml:"table_name"`
			CAGsi            string `yaml:"ca_gsi"`
			Endpoint         string `yaml:"endpoint"`
			RetryMaxAttempts *int   `yaml:"retry_max_attempts"`
			Timeout          *int   `yaml:"timeout"`
		} `yaml:"dynamodb"`
		FileDB *struct {
			File string `yaml:"file"`
		} `yaml:"file"`
	} `yaml:"db"`
	HTTP struct {
		Port               string `yaml:"port"`
		Domain             string `yaml:"domain"`
		ReadTimeout        *int   `yaml:"read_timeout"`
		WriteTimeout       *int   `yaml:"write_timeout"`
		ReadHeaderTimeout  *int   `yaml:"read_header_timeout"`
		MaxHeaderBytes     *int   `yaml:"max_header_bytes"`
		MaxRequestBytes    *int   `yaml:"max_request_bytes"`
		CacheControlMaxAge *int   `yaml:"cache_control_max_age"`
	} `yaml:"http"`
}

// Supported CA DB type.
type CADBType int

const (
	// File DB.
	FileDBType CADBType = iota
	// DynamoDB.
	DynamoDBType
)

// Supported log format.
type LogFormat int

const (
	// JSON format.
	JSONFormat LogFormat = iota
	// Pretty format (human readable).
	PrettyFormat
)

// Default values.
const (
	ReadTimeOutDefault       = 30
	WriteTimeOutDefault      = 0
	ReadHeaderTimeoutDefault = 10
	MaxHeaderBytesDefault    = 1048576
	MaxRequestBytesDefault   = 256
	DynamoDBTimeoutDefault   = 60
	IntervalDefault          = 60
	DelayDefault             = 5
	LogLevelDefault          = "info"
	LogFormtDefault          = "json"
	ExpirationDefault        = "ignore"
)

// MissingParameterError is used when configuration paramemter is missing.
type MissingParameterError struct {
	Param string
}

func (e MissingParameterError) Error() string {
	return fmt.Sprintf(
		"'%s' parameter is not set or contains an empty value.", e.Param,
	)
}

// InvalidParameterError is used when configuration paramemter is invalid.
type InvalidParameterError struct {
	param       string
	description string
}

func (e InvalidParameterError) Error() string {
	return fmt.Sprintf(
		"'%s' parameter is invalid: %s",
		e.param,
		e.description,
	)
}

const (
	errsCap2  = 2
	errsCap4  = 4
	errsCap8  = 8
	errsCap16 = 6
	errsCap32 = 32
)

func markMissRequiredStr(sp string, spName string, errs []error) (string, []error) {
	if sp == "" {
		errs = append(errs, MissingParameterError{spName})
	}
	return sp, errs
}

// VerifyResponderConfig verifies .Log.
func (y ConfigYAML) VerifyLogConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap2)

	if y.Log.Level == "" {
		nCfg.LogLevel = LogLevelDefault
	} else if matched, _ := regexp.MatchString(`\A(?:error|warn|info|debug)\z`, y.Log.Level); !matched {
		errs = append(errs, InvalidParameterError{"log.level", "[error|warn|info|debug]"})
	} else {
		nCfg.LogLevel = y.Log.Level
	}

	switch nCfg.LogLevel {
	case "debug":
		nCfg.ZerologLevel = zerolog.DebugLevel
	case "info":
		nCfg.ZerologLevel = zerolog.InfoLevel
	case "warn":
		nCfg.ZerologLevel = zerolog.WarnLevel
	case "error":
		nCfg.ZerologLevel = zerolog.ErrorLevel
	}

	if y.Log.Format == "" {
		nCfg.LogFormat = LogFormtDefault
	} else if matched, _ := regexp.MatchString(`\A(?:json|pretty)\z`, y.Log.Format); !matched {
		errs = append(errs, InvalidParameterError{"log.format", "[json|pretty]"})
	} else {
		nCfg.LogFormat = y.Log.Format
	}

	switch nCfg.LogFormat {
	case "json":
		nCfg.ZerologFormat = JSONFormat
	case "pretty":
		nCfg.ZerologFormat = PrettyFormat
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// VerifyResponderConfig verifies .Responder.
func (y ConfigYAML) VerifyResponderConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap4)

	// Responder.CA              Required
	nCfg.CA, errs = markMissRequiredStr(y.Responder.CA, "responder.ca", errs)
	// Responder.Certificate     Required
	nCfg.Certificate, errs = markMissRequiredStr(y.Responder.Certificate, "responder.responder_certificate", errs)
	// Responder.Key             Required (file or envionment variable)
	nCfg.Key = y.Responder.Key
	// Responder.Issuer          Required
	nCfg.Issuer, errs = markMissRequiredStr(y.Responder.Issuer, "responder.issuer_certificate", errs)

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// VerifyCacheConfig verifies .Caches.
func (y ConfigYAML) VerifyCacheConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap4)

	switch {
	case y.Cache.Interval == nil:
		nCfg.Interval = IntervalDefault
	case *y.Cache.Interval <= 0:
		errs = append(errs, InvalidParameterError{"cache.interval", "the number of seconds must be > 0"})
	default:
		nCfg.Interval = *y.Cache.Interval
	}

	switch {
	case y.Cache.Delay == nil:
		nCfg.Delay = DelayDefault
	case *y.Cache.Delay < 0:
		errs = append(errs, InvalidParameterError{"cache.delay", "the number of seconds must be >= 0"})
	case *y.Cache.Delay > nCfg.Interval:
		errs = append(errs, InvalidParameterError{"cache.delay", "cache.delay must be <= cache.interval"})
	default:
		nCfg.Delay = *y.Cache.Delay
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// VerifyDynamoDBConfig verifies .DB.DynamoDB.
func (y ConfigYAML) VerifyDynamoDBConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap8)

	// DB.DynamoDB.Region            Required
	nCfg.DynamoDBRegion, errs = markMissRequiredStr(y.DB.DynamoDB.Region, "db.dynamodb.region", errs)
	// DB.DynamoDB.TableName         Required
	nCfg.DynamoDBTableName, errs = markMissRequiredStr(y.DB.DynamoDB.TableName, "db.dynamodb.table_name", errs)
	// DB.DynamoDB.CAGsi             Required
	nCfg.DynamoDBCAGsi, errs = markMissRequiredStr(y.DB.DynamoDB.CAGsi, "db.dynamodb.ca_gsi", errs)

	// DB.DynamoDB.Endpoint          Optional (default: DynamoDB Cloud)
	if y.DB.DynamoDB.Endpoint != "" {
		if matched, _ := regexp.MatchString(`\Ahttps?://`, y.DB.DynamoDB.Endpoint); !matched {
			errs = append(errs, InvalidParameterError{
				"db.dynamodb.endpoint",
				"url must start from 'http://' or 'https://'",
			})
		}
	}
	nCfg.DynamoDBEndpoint = y.DB.DynamoDB.Endpoint

	// DB.DynamoDB.RetryMaxAttempts  Optional (default: 0)
	switch {
	case y.DB.DynamoDB.RetryMaxAttempts == nil:
		nCfg.DynamoDBRetryMaxAttempts = 0
	case *y.DB.DynamoDB.RetryMaxAttempts < 0:
		errs = append(errs, InvalidParameterError{
			"db.dynamodb.retry_max_attempts",
			"the number of retries must be >= 0",
		})
	default:
		nCfg.DynamoDBRetryMaxAttempts = *y.DB.DynamoDB.RetryMaxAttempts
	}

	// DB.DynamoDB.RetryMaxAttempts  Optional (default: 0)
	switch {
	case y.DB.DynamoDB.Timeout == nil:
		nCfg.DynamoDBTimeout = DynamoDBTimeoutDefault
	case *y.DB.DynamoDB.Timeout <= 0:
		errs = append(errs, InvalidParameterError{
			"db.dynamodb.timeout",
			"the number of seconds for timeout must be > 0",
		})
	default:
		nCfg.DynamoDBTimeout = *y.DB.DynamoDB.Timeout
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// VerifyFileDBConfig verifies .DB.FileDB.
func (y ConfigYAML) VerifyFileDBConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap2)

	// .DB.FileDB.File
	nCfg.FileDBFile, errs = markMissRequiredStr(y.DB.FileDB.File, "db.file.file", errs)

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// VerifyDBConfig verifies .DB.
func (y ConfigYAML) VerifyDBConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap16)

	dupN := 0

	// .DB.FileDB
	if y.DB.FileDB != nil {
		nCfg, errs = y.VerifyFileDBConfig(nCfg)
		nCfg.DBType = FileDBType
		dupN++
	}

	// .DB.DynamoDB
	if y.DB.DynamoDB != nil {
		nCfg, errs = y.VerifyDynamoDBConfig(nCfg)
		nCfg.DBType = DynamoDBType
		dupN++
	}

	if dupN == 0 {
		errs = []error{MissingParameterError{"db.<db-type>"}}
		return cfg, errs
	}

	if dupN > 1 {
		errs = []error{InvalidParameterError{"db.<db-type>", "DB type is exclusive"}}
		return cfg, errs
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

func specOrDefInt(i *int, def int) int {
	if i == nil {
		return def
	}
	return *i
}

// VerifyHTTPConfig verifies .HTTP.
func (y ConfigYAML) VerifyHTTPConfig(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap4)

	// HTTP.Port                 Optional
	if y.HTTP.Port == "" {
		nCfg.Port = "80"
	} else if matched, _ := regexp.MatchString(`\A[1-9][0-9]*\z`, y.HTTP.Port); !matched {
		errs = append(errs, InvalidParameterError{"http.port", "must be the valid port number"})
	} else {
		nCfg.Port = y.HTTP.Port
	}
	// HTTP.Domain               Optional
	nCfg.Domain = y.HTTP.Domain
	// HTTP.ReadTimeout          Optional
	nCfg.ReadTimeout = specOrDefInt(y.HTTP.ReadTimeout, ReadTimeOutDefault)
	// HTTP.WriteTimeout         Optional
	nCfg.WriteTimeout = specOrDefInt(y.HTTP.WriteTimeout, WriteTimeOutDefault)
	// HTTP.ReadHeaderTimeout    Optional
	nCfg.ReadHeaderTimeout = specOrDefInt(y.HTTP.ReadHeaderTimeout, ReadHeaderTimeoutDefault)
	// HTTP.MaxHeaderBytes       Optional
	nCfg.MaxHeaderBytes = specOrDefInt(y.HTTP.MaxHeaderBytes, MaxHeaderBytesDefault)
	// HTTP.MaxHeaderBytes       Optional
	nCfg.MaxRequestBytes = specOrDefInt(y.HTTP.MaxRequestBytes, MaxRequestBytesDefault)

	switch {
	case y.HTTP.CacheControlMaxAge == nil:
		nCfg.CacheControlMaxAge = nCfg.Interval
	case *y.HTTP.CacheControlMaxAge <= 0:
		errs = append(
			errs,
			InvalidParameterError{"http.cache_control_max_age", "cache-control max-age must be > 0"},
		)
	case *y.HTTP.CacheControlMaxAge > nCfg.Interval:
		errs = append(
			errs,
			InvalidParameterError{"http.cache_control_max_age", "cache-control max-age must be <= cache.interval"},
		)
	default:
		nCfg.CacheControlMaxAge = *y.HTTP.CacheControlMaxAge
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

// Verify verifies the configuration root '.' using the ConfigYAML.Verify* methods.
// If it detects any invalid parameters, it returns an error slice.
// If there are no errors, it returns nil.
func (y ConfigYAML) Verify(cfg DyOCSPConfig) (DyOCSPConfig, []error) {
	nCfg := cfg
	errs := make([]error, 0, errsCap32)

	// .Version  Required 0.1 only
	nCfg.Version, errs = markMissRequiredStr(y.Version, "version", errs)
	if y.Version != "" {
		if matched, _ := regexp.MatchString(`\A(?:0.1)\z`, y.Version); !matched {
			errs = append(errs, InvalidParameterError{"version", "[0.1]"})
		}
	}

	// .Strict  Optional
	nCfg.Strict = y.Strict

	// .Expiration  Optional
	if y.Expiration == "" {
		nCfg.Expiration = ExpirationDefault
	} else if matched, _ := regexp.MatchString(`\A(?:ignore|warn|invalid)\z`, y.Expiration); !matched {
		errs = append(errs, InvalidParameterError{"expiration", "[ignore|warn|invalid]"})
	} else {
		nCfg.Expiration = y.Expiration
	}

	// .Log.Level  Optional error, warn, info, debug (default: info)
	nCfg, logErrs := y.VerifyLogConfig(nCfg)
	if len(logErrs) != 0 {
		errs = append(errs, logErrs...)
	}

	// .Responder
	nCfg, responderErrs := y.VerifyResponderConfig(nCfg)
	if len(responderErrs) != 0 {
		errs = append(errs, responderErrs...)
	}

	// .Cache
	nCfg, cacheErrs := y.VerifyCacheConfig(nCfg)
	if len(cacheErrs) != 0 {
		errs = append(errs, cacheErrs...)
	}

	// .DB
	nCfg, dbErrs := y.VerifyDBConfig(nCfg)
	if len(dbErrs) != 0 {
		errs = append(errs, dbErrs...)
	}

	// .HTTP
	nCfg, httpErrs := y.VerifyHTTPConfig(nCfg)
	if len(httpErrs) != 0 {
		errs = append(errs, httpErrs...)
	}

	if len(errs) != 0 {
		return cfg, errs
	}
	return nCfg, nil
}

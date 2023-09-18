package config

import (
	"os"
	"reflect"
	"testing"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

func testUnmarshalConfigFIle(t *testing.T, file string) ConfigYAML {
	t.Helper()

	confFile, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config ConfigYAML
	err = yaml.Unmarshal(confFile, &config)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func convConfigYAMLToDyOCSPConfig(cfgYml ConfigYAML) DyOCSPConfig {
	var cfg DyOCSPConfig
	cfg.Version = cfgYml.Version
	cfg.Strict = cfgYml.Strict
	cfg.Expiration = cfgYml.Expiration

	cfg.LogLevel = cfgYml.Log.Level
	switch cfg.LogLevel {
	case "debug":
		cfg.ZerologLevel = zerolog.DebugLevel
	case "info":
		cfg.ZerologLevel = zerolog.InfoLevel
	case "warn":
		cfg.ZerologLevel = zerolog.WarnLevel
	case "error":
		cfg.ZerologLevel = zerolog.ErrorLevel
	}

	cfg.LogFormat = cfgYml.Log.Format
	switch cfg.LogFormat {
	case "json":
		cfg.ZerologFormat = JSONFormat
	case "pretty":
		cfg.ZerologFormat = PrettyFormat
	}

	cfg.CA = cfgYml.Responder.CA
	cfg.Certificate = cfgYml.Responder.Certificate
	cfg.Key = cfgYml.Responder.Key
	cfg.Issuer = cfgYml.Responder.Issuer

	cfg.Interval = *cfgYml.Cache.Interval
	cfg.Delay = *cfgYml.Cache.Delay

	if cfgYml.DB.DynamoDB != nil {
		cfg.DynamoDBRegion = cfgYml.DB.DynamoDB.Region
		cfg.DynamoDBTableName = cfgYml.DB.DynamoDB.TableName
		cfg.DynamoDBCAGsi = cfgYml.DB.DynamoDB.CAGsi
		cfg.DynamoDBEndpoint = cfgYml.DB.DynamoDB.Endpoint
		cfg.DynamoDBRetryMaxAttempts = *cfgYml.DB.DynamoDB.RetryMaxAttempts
		cfg.DynamoDBTimeout = *cfgYml.DB.DynamoDB.Timeout
		cfg.DBType = DynamoDBType
	}

	if cfgYml.DB.FileDB != nil {
		cfg.FileDBFile = cfgYml.DB.FileDB.File
		cfg.DBType = FileDBType
	}

	cfg.Port = cfgYml.HTTP.Port
	cfg.Domain = cfgYml.HTTP.Domain
	cfg.ReadTimeout = *cfgYml.HTTP.ReadTimeout
	cfg.WriteTimeout = *cfgYml.HTTP.WriteTimeout
	cfg.ReadHeaderTimeout = *cfgYml.HTTP.ReadHeaderTimeout
	cfg.MaxHeaderBytes = *cfgYml.HTTP.MaxHeaderBytes
	cfg.MaxRequestBytes = *cfgYml.HTTP.MaxRequestBytes
	if cfgYml.HTTP.CacheControlMaxAge == nil {
		cfg.CacheControlMaxAge = cfg.Interval
	} else {
		cfg.CacheControlMaxAge = *cfgYml.HTTP.CacheControlMaxAge
	}

	return cfg
}

func TestConfigYAML_Verify_CheckOptoinalParams_WithDyanmoDB(t *testing.T) {
	t.Parallel()

	baseYml := testUnmarshalConfigFIle(t, "testdata/base-dynamodb.yml")
	minYml := testUnmarshalConfigFIle(t, "testdata/minimum-dynamodb.yml")
	defaultYml := testUnmarshalConfigFIle(t, "testdata/default-dynamodb.yml")

	data := []struct {
		testcase string
		// test data
		cfgYml ConfigYAML
		// want
		wantCfg DyOCSPConfig
	}{
		{
			"OK: All param is set, any params are not changed",
			baseYml,
			convConfigYAMLToDyOCSPConfig(baseYml),
		},
		{
			"OK: All param is set, default params are set",
			minYml,
			convConfigYAMLToDyOCSPConfig(defaultYml),
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testcase, func(t *testing.T) {
			t.Parallel()
		})

		var cfg DyOCSPConfig
		rCfg, err := d.cfgYml.Verify(cfg)
		if err != nil {
			t.Fatalf("unexpected Error '%#v' with: %#v", err, rCfg)
		}
		if !reflect.DeepEqual(d.wantCfg, rCfg) {
			t.Fatalf("Expected config is '%#v' but got: %#v", d.wantCfg, rCfg)
		}
	}
}

func TestConfigYAML_Verify_Errors(t *testing.T) {
	t.Parallel()

	data := []struct {
		testCase string
		// test data
		cfgFile string
		// want
		errs []error
	}{
		{
			"check invalid value with DynamoDB",
			"testdata/bad-dynamodb.yml",
			[]error{
				InvalidParameterError{"version", "[0.1]"},
				InvalidParameterError{"expiration", "[ignore|warn|invalid]"},
				InvalidParameterError{"log.level", "[error|warn|info|debug]"},
				InvalidParameterError{"log.format", "[json|pretty]"},
				InvalidParameterError{"cache.interval", "the number of seconds must be > 0"},
				InvalidParameterError{"cache.delay", "the number of seconds must be >= 0"},
				InvalidParameterError{"db.dynamodb.endpoint", "url must start from 'http://' or 'https://'"},
				InvalidParameterError{"db.dynamodb.retry_max_attempts", "the number of retries must be >= 0"},
				InvalidParameterError{"db.dynamodb.timeout", "the number of seconds for timeout must be > 0"},
				InvalidParameterError{"http.port", "must be the valid port number"},
				InvalidParameterError{"http.cache_control_max_age", "cache-control max-age must be > 0"},
			},
		},
		{
			"check invalid value with DynamoDB",
			"testdata/bad-cache_control_max_age.yml",
			[]error{
				InvalidParameterError{
					"http.cache_control_max_age", "cache-control max-age must be <= cache.interval",
				},
			},
		},
		{
			"check invalid value with DynamoDB",
			"testdata/bad-delay.yml",
			[]error{
				InvalidParameterError{
					"cache.delay", "cache.delay must be <= cache.interval",
				},
			},
		},
		{
			"check required param with empty config",
			"",
			[]error{
				MissingParameterError{"version"},
				MissingParameterError{"responder.ca"},
				MissingParameterError{"responder.responder_certificate"},
				MissingParameterError{"responder.issuer_certificate"},
				MissingParameterError{"db.<db-type>"},
			},
		},
		{
			"check required param with DynamoDB",
			"testdata/empty-dynamodb.yml",
			[]error{
				MissingParameterError{"db.dynamodb.region"},
				MissingParameterError{"db.dynamodb.table_name"},
				MissingParameterError{"db.dynamodb.ca_gsi"},
			},
		},
		{
			"check required param with FileDB",
			"testdata/empty-filedb.yml",
			[]error{
				MissingParameterError{"db.file.file"},
			},
		},
		{
			"Check invalid value with duplicated DB",
			"testdata/duplicated-db.yml",
			[]error{
				InvalidParameterError{"db.<db-type>", "DB type is exclusive"},
			},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			var yml ConfigYAML
			if d.cfgFile != "" {
				yml = testUnmarshalConfigFIle(t, d.cfgFile)
			}

			var cfg DyOCSPConfig
			_, resultErrs := yml.Verify(cfg)
			if resultErrs == nil {
				t.Fatal("Any error is not returned.")
			}

			if !reflect.DeepEqual(d.errs, resultErrs) {
				t.Fatalf("Expected errors is '%#v' but got: %#v", d.errs, resultErrs)
			}
		})
	}
}

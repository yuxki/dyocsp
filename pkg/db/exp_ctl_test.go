package db

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"
)

type StubLogger struct {
	logMsg string
}

func (s *StubLogger) InvalidMsg(serial string, msg string) {
	s.logMsg += fmt.Sprintf("StubLogger Invalid: %s: %s", msg, serial)
}

func (s *StubLogger) WarnMsg(serial *big.Int, msg string) {
	s.logMsg += fmt.Sprintf("StubLogger Warning: %s: %s", msg, serial.Text(SerialBase))
}

func TestExpirationControl_Do(t *testing.T) {
	t.Parallel()

	serial, ok := new(big.Int).SetString("72344BF34067BBA31EF44587CBFB16631332CD23", 16)
	if !ok {
		t.Fatal("Failed create a valid serial for testing.")
	}
	expiredSerial, ok := new(big.Int).SetString("1111111111111111111111111111111111111111", 16)
	if !ok {
		t.Fatal("Failed create a valid serial for testing.")
	}

	data := []struct {
		testCase string
		testOpt  string
		// test data
		now     time.Time
		dur     time.Duration
		entries []CertificateEntry
		// want
		valids       []CertificateEntry
		loggerOutput string
	}{
		{
			testCase: "No options, there is no invalid",
			testOpt:  "none",
			now:      time.Date(2033, 6, 9, 12, 33, 17, 0, time.UTC),
			dur:      time.Hour * 80,
			entries: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    expiredSerial,
					RevType:   "V",
					ExpDate:   time.Date(2033, 7, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Time{},
					CRLReason: NotRevoked,
					Errors:    map[InvalidWith]error{},
				},
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			valids: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    expiredSerial,
					RevType:   "V",
					ExpDate:   time.Date(2033, 7, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Time{},
					CRLReason: NotRevoked,
					Errors:    map[InvalidWith]error{},
				},
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			loggerOutput: "",
		},
		{
			testCase: "No options, there is a invalid",
			testOpt:  "none",
			now:      time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			dur:      time.Hour * 1,
			entries: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    expiredSerial,
					RevType:   "V",
					ExpDate:   time.Date(2033, 7, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Time{},
					CRLReason: NotRevoked,
					Errors:    map[InvalidWith]error{},
				},
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			valids: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			loggerOutput: "StubLogger Invalid: It is no longer valid because it has exceeded expiration date: 1111111111111111111111111111111111111111",
		},
		{
			testCase: "warnOnExpiration is true.",
			testOpt:  "WithWarnOnExpiration",
			now:      time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			dur:      time.Hour * 1,
			entries: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    expiredSerial,
					RevType:   "V",
					ExpDate:   time.Date(2033, 7, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Time{},
					CRLReason: NotRevoked,
					Errors:    map[InvalidWith]error{},
				},
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			valids: []CertificateEntry{
				{
					Ca:        "sub-ca",
					Serial:    expiredSerial,
					RevType:   "V",
					ExpDate:   time.Date(2033, 7, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Time{},
					CRLReason: NotRevoked,
					Errors:    map[InvalidWith]error{},
				},
				{
					Ca:        "sub-ca",
					Serial:    serial,
					RevType:   "R",
					ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
					RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
					CRLReason: KeyCompromise,
					Errors:    map[InvalidWith]error{},
				},
			},
			loggerOutput: "StubLogger Warning: It is valid but it has exceeded expiration date: 1111111111111111111111111111111111111111",
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()
			var logger StubLogger

			var ctl *ExpirationControl
			switch d.testOpt {
			case "none":
				ctl = NewExpirationControl(WithLogger(&logger))
			case "WithWarnOnExpiration":
				ctl = NewExpirationControl(WithLogger(&logger), WithWarnOnExpiration())
			default:
				t.Fatal("Undefined testopt: " + d.testOpt)
			}

			valids := ctl.Do(d.now, d.entries)

			if !reflect.DeepEqual(valids, d.valids) {
				t.Errorf("Expected valids are %#v, but got: %#v", d.valids, valids)
			}

			if logger.logMsg != d.loggerOutput {
				t.Errorf("Expected logMsg are %#v, but got: %#v", d.loggerOutput, logger.logMsg)
			}
		})
	}
}

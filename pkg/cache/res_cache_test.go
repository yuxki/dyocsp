package cache

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

func TestCreatePreSignedResponseCache(t *testing.T) {
	t.Parallel()

	validSerial, ok := new(big.Int).SetString("72344BF34067BBA31EF44587CBFB16631332CD23", 16)
	if !ok {
		t.Fatal("Failed create a valid serial for testing.")
	}

	maxSerial, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01", 16)
	if !ok {
		t.Fatal("Failed create a valid serial for testing.")
	}

	data := []struct {
		testCase string
		// test data
		entry         db.CertificateEntry
		interval      time.Duration
		invalidReason db.InvalidWith
		// want
		status           int
		revokedAt        time.Time
		revocationReason int
		nextUpdate       time.Time
		errMsg           string
	}{
		{
			"OK: status good, valid certificate",
			db.CertificateEntry{
				Ca:        "sub-ca",
				Serial:    validSerial,
				RevType:   "V",
				ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
				RevDate:   time.Time{},
				CRLReason: db.NotRevoked,
				Errors:    map[db.InvalidWith]error{},
			},
			time.Hour * 10,
			db.NoError,
			ocsp.Good,
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			ocsp.Unspecified,
			time.Date(2023, 8, 9, 22, 30, 0, 0, time.UTC),
			"",
		},
		{
			"OK: status good, revoked certificate",
			db.CertificateEntry{
				Ca:        "sub-ch",
				Serial:    validSerial,
				RevType:   "R",
				ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
				RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
				CRLReason: ocsp.KeyCompromise,
				Errors:    map[db.InvalidWith]error{},
			},
			time.Hour * 10,
			db.NoError,
			ocsp.Revoked,
			time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
			ocsp.KeyCompromise,
			time.Date(2023, 8, 9, 22, 30, 0, 0, time.UTC),
			"",
		},
		{
			"NG: Invalid Serial: nil",
			db.CertificateEntry{
				Ca:        "sub-ca",
				Serial:    nil,
				RevType:   "V",
				ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
				RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
				CRLReason: ocsp.KeyCompromise,
				Errors:    map[db.InvalidWith]error{},
			},
			time.Hour * 10,
			db.NoError,
			ocsp.Revoked,
			time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
			ocsp.KeyCompromise,
			time.Date(2023, 8, 9, 22, 30, 0, 0, time.UTC),
			"pre-signed cache could not be created: entry.Serial is nil.",
		},
		{
			"NG: Invalid Serial: over 20 octets max value",
			db.CertificateEntry{
				Ca:        "sub-ca",
				Serial:    maxSerial,
				RevType:   "V",
				ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
				RevDate:   time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
				CRLReason: ocsp.KeyCompromise,
				Errors:    map[db.InvalidWith]error{},
			},
			time.Hour * 10,
			db.NoError,
			ocsp.Revoked,
			time.Date(2023, 10, 9, 12, 33, 17, 0, time.UTC),
			ocsp.KeyCompromise,
			time.Date(2023, 8, 9, 22, 30, 0, 0, time.UTC),
			"pre-signed cache could not be created: entry.Serial exceeds 20 octets.",
		},
		{
			"NG: Has any error",
			db.CertificateEntry{
				Ca:        "sub-ca",
				Serial:    validSerial,
				RevType:   "V",
				ExpDate:   time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
				RevDate:   time.Time{},
				CRLReason: -1,
				Errors:    map[db.InvalidWith]error{},
			},
			time.Hour * 10,
			db.MalformSerial,
			ocsp.Good,
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			ocsp.Unspecified,
			time.Date(2033, 8, 9, 22, 30, 0, 0, time.UTC),
			"pre-signed cache could not be created: entry already contains a previously identified error.",
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			d.entry.Errors[d.invalidReason] = errors.New("invalid")
			thisUpdate := time.Date(2023, 8, 9, 12, 30, 0, 0, time.UTC)
			cache, err := CreatePreSignedResponseCache(d.entry, thisUpdate, time.Hour*10)

			if d.errMsg == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if err.Error() != d.errMsg {
					t.Fatalf("Expected '%#v' error msg but got: %#v", d.errMsg, err.Error())
				}
				return
			}

			// SerialNumber
			if cache.template.SerialNumber.Cmp(validSerial) != 0 {
				t.Errorf(
					"serial expected %#v, but got: %#v", validSerial.Text(16),
					cache.template.SerialNumber.Text(16),
				)
			}

			// Status
			if cache.template.Status != d.status {
				t.Errorf("status expected %#v, but got: %#v", d.status, cache.template.Status)
			}

			// RevokedAt
			if d.revokedAt.Compare(cache.template.RevokedAt) != 0 {
				t.Errorf("revokedAt expected %#v, but got: %#v", d.revokedAt, cache.template.RevokedAt)
			}

			// RevocationReason
			if cache.template.RevocationReason != d.revocationReason {
				t.Errorf(
					"RevocationReason expected %#v, but got: %#v",
					d.revocationReason, cache.template.RevocationReason,
				)
			}

			// ThisUpdate
			if thisUpdate.Compare(cache.template.ThisUpdate) != 0 {
				t.Errorf("thisUpdate expected %#v, but got: %#v", thisUpdate, cache.template.ThisUpdate)
			}

			// NextUpdate
			if d.nextUpdate.Compare(cache.template.NextUpdate) != 0 {
				t.Errorf("nextUpdate expected %#v, but got: %#v", d.nextUpdate, cache.template.NextUpdate)
			}
		})
	}
}

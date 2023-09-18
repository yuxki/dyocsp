package db

import (
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestEntryExchange_ParseCertificateEntry(t *testing.T) {
	t.Parallel()
	data := []struct {
		testCase string
		// test data
		itmdEntry IntermidiateEntry
		// want
		expDate       time.Time
		revDate       time.Time
		crlReason     EntryCRLReason
		invalidReason InvalidWith
		errMsg        string
	}{
		{
			"OK: valid",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "V",
				ExpDate:   "330809123317Z",
				RevDate:   "",
				CRLReason: "",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Time{},
			NotRevoked,
			0,
			"",
		},
		{
			"OK: revoked UTC TIME YY < 50",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631Z",
				CRLReason: "unspecified",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Date(2023, 8, 13, 12, 56, 31, 0, time.UTC),
			Unspecified,
			0,
			"",
		},
		{
			"OK: revoked UTC TIME YY >= 50",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "500813125631Z",
				CRLReason: "unspecified",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Date(1950, 8, 13, 12, 56, 31, 0, time.UTC),
			Unspecified,
			0,
			"",
		},
		{
			"OK: revoked GeneralizedTime",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "20330809123317Z",
				RevDate:   "20230813125631Z",
				CRLReason: "unspecified",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Date(2023, 8, 13, 12, 56, 31, 0, time.UTC),
			Unspecified,
			0,
			"",
		},
		{
			"NG: Serial: malform",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
				RevType:   "V",
				ExpDate:   "330809123317Z",
				RevDate:   "",
				CRLReason: "",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Time{},
			NotRevoked,
			MalformSerial,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid serial: ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
		},
		{
			"NG: Serial: over 20 octet",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23FF",
				RevType:   "V",
				ExpDate:   "330809123317Z",
				RevDate:   "",
				CRLReason: "",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Time{},
			NotRevoked,
			MalformSerial,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid serial: 72344BF34067BBA31EF44587CBFB16631332CD23FF",
		},
		{
			"NG: RevType (undefined rev_type)",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "Z",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631Z",
				CRLReason: "unspecified",
			},
			time.Time{},
			time.Time{},
			Unspecified,
			UndefinedRevType,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_type: Z",
		},
		{
			"NG: RevType (conflicting situations: V but rev_date exists)",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "V",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631Z",
				CRLReason: "",
			},
			time.Time{},
			time.Time{},
			Unspecified,
			UndefinedRevType,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_type: rev_status is V but rev_date exists",
		},
		{
			"NG: RevType (conflicting situations: V but crl_reason exists)",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "V",
				ExpDate:   "330809123317Z",
				RevDate:   "",
				CRLReason: "unspecified",
			},
			time.Time{},
			time.Time{},
			Unspecified,
			UndefinedRevType,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_type: rev_status is V but crl_reason exists",
		},
		{
			"NG: RevType (conflicting situations: R but rev_date does not exist)",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "",
				CRLReason: "unspecified",
			},
			time.Time{},
			time.Time{},
			Unspecified,
			UndefinedRevType,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_type: rev_status is R but rev_date does not exist",
		},
		{
			"NG: RevType (conflicting situations: R but crl_reason is not exists)",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631Z",
				CRLReason: "",
			},
			time.Time{},
			time.Time{},
			Unspecified,
			UndefinedRevType,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_type: rev_status is R but crl_reason does not exist",
		},
		{
			"NG: ExpDate",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317",
				RevDate:   "230813125631Z",
				CRLReason: "unspecified",
			},
			time.Time{},
			time.Date(2023, 8, 13, 12, 56, 31, 0, time.UTC),
			Unspecified,
			MalformExpDate,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid exp_date: 330809123317",
		},
		{
			"NG: RevDate",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631",
				CRLReason: "unspecified",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Time{},
			Unspecified,
			MalformRevDate,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid rev_date: 230813125631",
		},
		{
			"NG: CRLReason",
			IntermidiateEntry{
				Ca:        "sub-ca",
				Serial:    "72344BF34067BBA31EF44587CBFB16631332CD23",
				RevType:   "R",
				ExpDate:   "330809123317Z",
				RevDate:   "230813125631Z",
				CRLReason: "ng",
			},
			time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC),
			time.Date(2023, 8, 13, 12, 56, 31, 0, time.UTC),
			Unspecified,
			UndefinedCRLReason,
			"failed exchange from Intermediate Entry to Certificate Entry: invalid crl_reason: ng",
		},
	}

	exchange := NewEntryExchange()
	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			entry := exchange.ParseCertificateEntry(d.itmdEntry)

			if d.errMsg == "" {
				if entry.Errors[d.invalidReason] != nil {
					t.Fatal("Unexpected error found.")
				}
			} else {
				if entry.Errors[d.invalidReason].Error() != d.errMsg {
					t.Fatalf(
						"Expected '%#v' error msg but got: %#v", d.errMsg, entry.Errors[d.invalidReason].Error(),
					)
				}
				return
			}

			if entry.Ca != d.itmdEntry.Ca {
				t.Errorf("Ca is changed: %#v", entry.Ca)
			}

			waitSerial, _ := new(big.Int).SetString(d.itmdEntry.Serial, SerialBase)
			if entry.Serial.Cmp(waitSerial) != 0 {
				t.Errorf("Serial %#v is changed: %#v", d.itmdEntry.Serial, entry.Serial)
			}

			if entry.RevType != EntryRevType(d.itmdEntry.RevType) {
				t.Errorf("RevType %#v is changed: %#v", d.itmdEntry.RevType, entry.RevType)
			}

			if !reflect.DeepEqual(entry.ExpDate, d.expDate) {
				t.Errorf("ExpDate %#v is changed: %#v", d.expDate, entry.ExpDate)
			}

			if !reflect.DeepEqual(entry.RevDate, d.revDate) {
				t.Errorf("RevDate %#v is changed: %#v", d.revDate, entry.RevDate)
			}

			if entry.CRLReason != d.crlReason {
				t.Errorf("CRLReason %#v is changed: %#v", d.crlReason, entry.CRLReason)
			}
		})
	}
}

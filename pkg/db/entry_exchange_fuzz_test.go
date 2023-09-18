package db

import "testing"

func FuzzEntryExchange_ParseCertificateEntry(f *testing.F) {
	exchange := NewEntryExchange()
	f.Add("ca", "724587CBFB16631332CD23", "Z", "330809123317Z", "330809123317Z", "abcd")
	f.Fuzz(func(t *testing.T, ca string, ser string, ret string, exd string, red string, crl string) {
		entry := IntermidiateEntry{
			Ca:        ca,
			Serial:    ser,
			RevType:   ret,
			ExpDate:   exd,
			RevDate:   red,
			CRLReason: crl,
		}
		exchange.ParseCertificateEntry(entry)
	})
}

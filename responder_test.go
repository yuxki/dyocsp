package dyocsp

import (
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

func cnvSerialStr2BigInt(serialStr string) *big.Int {
	bigInt := new(big.Int)
	serial, _ := bigInt.SetString(serialStr, db.SerialBase)
	return serial
}

func TestBuildResponder(t *testing.T) {
	t.Parallel()
	data := []struct {
		testCase string
		// test data
		rCertFile      string
		rCertSerialStr string
		rPrivKeyFile   string
		issuerCertFile string
		// want
		issuerCertSerialStr string
		responderType       AuthorizedType
		errMsg              string
	}{
		{
			"format: openssl x509 certificate, rsa pkcs8 key",
			"sub-ocsp-rsa.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5",
			"sub-ocsp-rsa-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"",
		},
		{
			"format: openssl x509 certificate, ec pkcs8 key",
			"sub-ocsp-ecparam.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			"sub-ocsp-ecparam-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"",
		},
		{
			"RFC 6960,4.2.2.2: sign the OCSP responses itself (OK)",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			"sub-ca-rsa-pkcs8.key",
			"root-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5",
			Itself,
			"",
		},
		{
			"RFC 6960,4.2.2.2: explicitly designate this authority to another entity (OK)",
			"sub-ocsp-ecparam.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			"sub-ocsp-ecparam-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"",
		},
		{
			"RFC 6960,4.2.2.2: explicitly designate this authority to another entity " +
				"(NG: Not includes a value of id-kp-OCSPSigning)",
			"sub-no-ocsp-rsa.crt",
			"1f8acd3265e5ba098dec495eece41c11ba093463",
			"sub-no-ocsp-rsa-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"invalid responder certificate: authorized reponder certificate does not include a value of id-kp-OCSPSigning.",
		},
		{
			"RFC 6960,4.2.2.2: explicitly designate this authority to another entity " +
				"(NG: Not Is the certificate of the CA that issued the certificate)",
			"sub-ocsp-ecparam.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			"sub-ocsp-ecparam-pkcs8.key",
			"root-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5",
			Delegation,
			"invalid issuer certificate: keyIdentifier is not matched the responder certificate.",
		},
		{
			"configuration: Not After date is past",
			"sub-expired-ocsp-rsa.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f7",
			"sub-expired-ocsp-rsa-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"invalid responder certificate: date of Not After is past.",
		},
		{
			"configuration: Not Before date is future",
			"sub-future-ocsp-rsa.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f8",
			"sub-future-ocsp-rsa-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"invalid responder certificate: date of Not Before is future.",
		},
		{
			"key pair: Bad pair of public key and private key",
			"sub-ocsp-rsa.crt",
			"8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5",
			"sub-ocsp-ecparam-pkcs8.key",
			"sub-ca-rsa.crt",
			"1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f6",
			Delegation,
			"invalid responder certificate: algorithm of private key does not matche the public key.",
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			rCertFilePem, err := os.ReadFile("testdata/" + d.rCertFile)
			if err != nil {
				t.Fatal(err)
			}

			rPrivKeyPem, err := os.ReadFile("testdata/" + d.rPrivKeyFile)
			if err != nil {
				t.Fatal(err)
			}

			issuerCertPem, err := os.ReadFile("testdata/" + d.issuerCertFile)
			if err != nil {
				t.Fatal(err)
			}

			responder, err := BuildResponder(
				rCertFilePem, rPrivKeyPem, issuerCertPem, time.Date(2024, 8, 9, 12, 30, 0, 0, time.UTC),
			)

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

			if responder.rCert.SerialNumber.Text(db.SerialBase) !=
				cnvSerialStr2BigInt(d.rCertSerialStr).Text(db.SerialBase) {
				t.Errorf("Type of rCert is not x509.Certificate: %#v", reflect.TypeOf(responder.rCert))
			}

			if responder.rPrivKey == nil {
				t.Errorf("Issuer Private key is not set on Responder")
			}

			if responder.issuerCert.SerialNumber.Text(db.SerialBase) !=
				cnvSerialStr2BigInt(d.issuerCertSerialStr).Text(db.SerialBase) {
				t.Errorf("Type of rCert is not x509.Certificate: %#v", reflect.TypeOf(responder.rCert))
			}

			if responder.AuthType != d.responderType {
				t.Fatalf("Expected ResponderType '%#v' but got: %#v", d.responderType, responder.AuthType)
			}
		})
	}
}

func TestBuildResponder_IssuerKeyNameHashes(t *testing.T) {
	t.Parallel()
	data := []struct {
		testCase string
		// test data
		rCertFile      string
		rPrivKeyFile   string
		issuerCertFile string
		// want
		issuerKeyHashSHA1  []byte
		issuerNameHashSHA1 []byte
	}{
		{
			"issuer name & key hashs: rsa",
			"sub-ocsp-rsa.crt",
			"sub-ocsp-rsa-pkcs8.key",
			"sub-ca-rsa.crt",
			[]byte{0xe9, 0x61, 0xfd, 0x3d, 0x66, 0x22, 0xec, 0x5e, 0x5a, 0xe7, 0xc9, 0x52, 0x61, 0xc4, 0xaf, 0x8c, 0x6d, 0x66, 0x70, 0x5d},
			[]byte{19, 227, 235, 142, 71, 110, 197, 189, 239, 55, 92, 120, 139, 166, 80, 251, 251, 72, 70, 129},
		},
		{
			"issuer name & key hashs: ecparam",
			"self-ecparam.crt",
			"self-ecparam.key",
			"self-ecparam.crt",
			[]byte{0xeb, 0xb9, 0xa8, 0x8d, 0x29, 0xf4, 0x52, 0x57, 0xde, 0x5d, 0x6, 0xea, 0x3d, 0xe4, 0x58, 0x6b, 0x31, 0xa9, 0xf5, 0x56},
			[]byte{43, 136, 163, 228, 65, 65, 77, 120, 171, 90, 36, 51, 134, 91, 254, 179, 168, 144, 173, 161},
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			rCertFilePem, err := os.ReadFile("testdata/" + d.rCertFile)
			if err != nil {
				t.Fatal(err)
			}

			rPrivKeyPem, err := os.ReadFile("testdata/" + d.rPrivKeyFile)
			if err != nil {
				t.Fatal(err)
			}

			issuerCertPem, err := os.ReadFile("testdata/" + d.issuerCertFile)
			if err != nil {
				t.Fatal(err)
			}

			responder, err := BuildResponder(
				rCertFilePem, rPrivKeyPem, issuerCertPem, time.Date(2024, 8, 9, 12, 30, 0, 0, time.UTC),
			)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(d.issuerKeyHashSHA1, responder.IssuerKeyHash.SHA1) {
				t.Errorf(
					"Expected IssuerKeyHash.SHA1 %#v but got : %#v",
					d.issuerKeyHashSHA1,
					responder.IssuerKeyHash.SHA1,
				)
			}

			if !reflect.DeepEqual(d.issuerNameHashSHA1, responder.IssuerNameHash.SHA1) {
				t.Errorf(
					"Expected IssuerNameHash.SHA1 %#v but got : %#v",
					d.issuerNameHashSHA1,
					responder.IssuerNameHash.SHA1,
				)
			}
		})
	}
}

func testCreateDirectResponder(t *testing.T) *Responder {
	t.Helper()

	rCertFilePem, err := os.ReadFile("testdata/sub-ca-rsa.crt")
	if err != nil {
		t.Fatal(err)
	}

	rPrivKeyPem, err := os.ReadFile("testdata/sub-ca-rsa-pkcs8.key")
	if err != nil {
		t.Fatal(err)
	}

	issuerCertPem, err := os.ReadFile("testdata/root-ca-rsa.crt")
	if err != nil {
		t.Fatal(err)
	}

	responder, err := BuildResponder(
		rCertFilePem, rPrivKeyPem, issuerCertPem, time.Date(2024, 8, 9, 12, 30, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	return responder
}

func testCreateDelegatedResponder(t *testing.T) *Responder {
	t.Helper()

	rCertFilePem, err := os.ReadFile("testdata/sub-ocsp-rsa.crt")
	if err != nil {
		t.Fatal(err)
	}

	rPrivKeyPem, err := os.ReadFile("testdata/sub-ocsp-rsa-pkcs8.key")
	if err != nil {
		t.Fatal(err)
	}

	issuerCertPem, err := os.ReadFile("testdata/sub-ca-rsa.crt")
	if err != nil {
		t.Fatal(err)
	}

	responder, err := BuildResponder(
		rCertFilePem, rPrivKeyPem, issuerCertPem, time.Date(2024, 8, 9, 12, 30, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}

	return responder
}

func TestResponder_SignCacheResponse(t *testing.T) {
	t.Parallel()

	responder := testCreateDelegatedResponder(t)

	serial, ok := new(big.Int).SetString("72344BF34067BBA31EF44587CBFB16631332CD23", db.SerialBase)
	if !ok {
		t.Fatal("String could not be *big.Int.")
	}

	data := []struct {
		testCase string
		// test data
		responder *Responder
		entry     db.CertificateEntry
		// want
		errMsg string
	}{
		{
			"OK: status good",
			responder,
			db.CertificateEntry{
				Ca:        "ca",
				Serial:    serial,
				RevType:   "V",
				ExpDate:   time.Date(2033, 8, 9, 12, 30, 0, 0, time.UTC),
				RevDate:   time.Time{},
				CRLReason: db.NotRevoked,
				Errors:    nil,
			},
			"",
		},
		{
			"OK: status revoked",
			responder,
			db.CertificateEntry{
				Ca:        "ca",
				Serial:    serial,
				RevType:   "R",
				ExpDate:   time.Date(2033, 8, 9, 12, 30, 0, 0, time.UTC),
				RevDate:   time.Date(2033, 8, 9, 11, 30, 0, 0, time.UTC),
				CRLReason: db.Unspecified,
				Errors:    nil,
			},
			"",
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testCase, func(t *testing.T) {
			t.Parallel()

			resCache, err := cache.CreatePreSignedResponseCache(
				d.entry, time.Date(2023, 8, 9, 12, 30, 0, 0, time.UTC), time.Second*120,
			)
			if err != nil {
				t.Fatal(err)
			}

			resCache, err = responder.SignCacheResponse(resCache)
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

			res, err := ocsp.ParseResponse(resCache.Response(), responder.rCert)
			if err != nil {
				t.Fatal(err)
			}

			if len(resCache.SHA1Hash()) != 20 {
				t.Errorf(
					"resCache.sha1Hash is not may not be a SHA1 hash of the OCSPResponse: %#v", resCache.SHA1Hash())
			}

			if res.Status != resCache.Template().Status {
				t.Errorf("State %#v is changed: %#v", resCache.Template().Status, res.Status)
			}

			if !reflect.DeepEqual(res.SerialNumber, resCache.Template().SerialNumber) {
				t.Errorf("State %#v is changed: %#v", resCache.Template().SerialNumber, res.SerialNumber)
			}

			if !reflect.DeepEqual(res.ThisUpdate, resCache.Template().ThisUpdate) {
				t.Errorf("State %#v is changed: %#v", resCache.Template().ThisUpdate, res.ThisUpdate)
			}

			if !reflect.DeepEqual(res.NextUpdate, resCache.Template().NextUpdate) {
				t.Errorf("State %#v is changed: %#v", resCache.Template().NextUpdate, res.NextUpdate)
			}

			if !reflect.DeepEqual(res.RevocationReason, resCache.Template().RevocationReason) {
				t.Errorf("State %#v is changed: %#v", resCache.Template().RevocationReason, res.RevocationReason)
			}
		})
	}
}

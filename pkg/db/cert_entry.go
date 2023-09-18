package db

import (
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	// The base of serial number.
	SerialBase = 16
	// The max octet length of serial number.
	SerialMaxOctetLength = 20
)

// This certificate revocation type is based on the index database of OpenSSL,
// which can be found at 'https://github.com/openssl/openssl'.
type EntryRevType string

const (
	// Valid status.
	Valid EntryRevType = "V"
	// Revoked status.
	Revoked EntryRevType = "R"
)

const (
	// YY Boundary value for RFC 5280: 4.1.2.5.1. UTCTime specification.
	// "Where YY is greater than or equal to 50, the year SHALL be
	// interpreted as 19YY; and Where YY is less than 50, the year SHALL be interpreted as 20YY."
	// (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1)
	UTCTimeYYBoundary = 50
)

const (
	// RFC 5280: 4.1.2.5.1. UTCTime.
	ASN1UTCTime = "060102150405Z"
	// RFC 5280: 4.1.2.5.2. GeneralizedTime.
	ASN1GeneralizedTime = "20060102150405Z"
)

type EntryCRLReason int

const (
	NotRevoked EntryCRLReason = ocsp.Unspecified - 1
	// RFC 5280: 5.3.1. Reason Codes.
	Unspecified          EntryCRLReason = ocsp.Unspecified
	KeyCompromise        EntryCRLReason = ocsp.KeyCompromise
	CACompromise         EntryCRLReason = ocsp.CACompromise
	AffiliationChanged   EntryCRLReason = ocsp.AffiliationChanged
	Superseded           EntryCRLReason = ocsp.Superseded
	CessationOfOperation EntryCRLReason = ocsp.CessationOfOperation
	CertificateHold      EntryCRLReason = ocsp.CertificateHold
	RemoveFromCRL        EntryCRLReason = ocsp.RemoveFromCRL
	PrivilegeWithdrawn   EntryCRLReason = ocsp.PrivilegeWithdrawn
	AACompromise         EntryCRLReason = ocsp.AACompromise
)

const (
	// Values of CRLReason.
	UnspecifieValue          = "unspecified"
	KeyCompromisValue        = "keyCompromise"
	CACompromisValue         = "CACompromise"
	AffiliationChangeValue   = "affiliationChanged"
	SupersedeValue           = "superseded"
	CessationOfOperatioValue = "cessationOfOperation"
	CertificateHolValue      = "certificateHold"
	RemoveFromCRValue        = "removeFromCRL"
	PrivilegeWithdrawValue   = "privilegeWithdrawn"
	AACompromisValue         = "AACompromise"
)

// Indexes of CertificateEntry.Erros.
type InvalidWith int

const (
	NoError InvalidWith = iota
	MalformSerial
	UndefinedRevType
	MalformExpDate
	MalformRevDate
	UndefinedCRLReason
)

// CertificateEntry is a revocation status entry used in the process of creating a
// pre-signed response cache with verification. In the process, it can contain errors
// in CertificateEntry.Errors that explain why the entry is invalid.
type CertificateEntry struct {
	Ca        string
	Serial    *big.Int
	RevType   EntryRevType
	ExpDate   time.Time
	RevDate   time.Time
	CRLReason EntryCRLReason
	Errors    map[InvalidWith]error
}

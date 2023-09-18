package db

import (
	"fmt"
	"math/big"
	"strconv"
	"time"
)

// InvalidEntryError provides an explanation for why a certificate revocation
// entry is invalid.
type InvalidEntryError struct {
	attr string
	msg  string
}

// InvalidEntryError returns error message.
func (e InvalidEntryError) Error() string {
	return "failed exchange from Intermediate Entry to Certificate Entry: invalid " + e.attr + ": " + e.msg
}

// EntryExchange provides methods for parsing CertificateEntry from
// IntermidiateEntry, but only in one direction.
type EntryExchange struct{}

// NewEntryExchange creates and returns s new EntryExchange instance.
func NewEntryExchange() EntryExchange {
	return EntryExchange{}
}

// SerialStrToBigInt convert serial number string to *big.Int.
func SerialStrToBigInt(serial string) (*big.Int, bool) {
	bIS := new(big.Int)
	bIS, ok := bIS.SetString(serial, SerialBase)
	if !ok {
		return nil, false
	}
	return bIS, true
}

// VerifySerial verifies serial string, and convert to *big.Int.
func (e *EntryExchange) VerifySerial(target string) (*big.Int, error) {
	// RFC rfc5280 4.1.2.2. Serial Number.
	if len(target) > SerialMaxOctetLength*2 {
		return nil, InvalidEntryError{
			attr: "serial",
			msg:  target,
		}
	}

	serial, ok := SerialStrToBigInt(target)
	if !ok {
		return nil, InvalidEntryError{
			attr: "serial",
			msg:  target,
		}
	}

	return serial, nil
}

// VerifyRevType verifies the value of the revocation type,
// revDate and crlReason are collected for the status.
// This function only accepts two status values: 'V' and 'R'. Any other status
// value will be considered invalid.
func (e *EntryExchange) VerifyRevType(
	target string, revDate string, crlReason string,
) (EntryRevType, error) {
	if target == string(Valid) {
		if revDate != "" {
			return "", InvalidEntryError{
				attr: "rev_type",
				msg:  fmt.Sprintf("rev_status is %s but rev_date exists", Valid),
			}
		}
		if crlReason != "" {
			return "", InvalidEntryError{
				attr: "rev_type",
				msg:  fmt.Sprintf("rev_status is %s but crl_reason exists", Valid),
			}
		}
		return EntryRevType(target), nil
	}

	if target == string(Revoked) {
		if revDate == "" {
			return "", InvalidEntryError{
				attr: "rev_type",
				msg:  fmt.Sprintf("rev_status is %s but rev_date does not exist", Revoked),
			}
		}
		if crlReason == "" {
			return "", InvalidEntryError{
				attr: "rev_type",
				msg:  fmt.Sprintf("rev_status is %s but crl_reason does not exist", Revoked),
			}
		}
		return EntryRevType(target), nil
	}

	return "", InvalidEntryError{
		attr: "rev_type",
		msg:  target,
	}
}

func (e *EntryExchange) convASN1DateStrToTime(target string) (time.Time, bool) {
	var date time.Time

	// RFC 5280 Section:4.1.2.5.1
	if len(target) == len(ASN1UTCTime) {
		yy, err := strconv.Atoi(target[:2])
		if err != nil {
			return date, false
		}

		if yy < UTCTimeYYBoundary {
			target = "20" + target
		} else {
			target = "19" + target
		}
	}

	date, err := time.Parse(ASN1GeneralizedTime, target)
	if err != nil {
		return date, false
	}

	return date, true
}

// VerifyExpDate verifies expiration date is valid and returns it
// as a time.Time value.
// It accepts following time format.
//   - UTCTime (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1)
//   - GeneralizedTime (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.2)
func (e *EntryExchange) VerifyExpDate(target string) (time.Time, error) {
	var date time.Time

	date, ok := e.convASN1DateStrToTime(target)
	if !ok {
		return date, InvalidEntryError{
			attr: "exp_date",
			msg:  target,
		}
	}

	return date, nil
}

// VerifyRevDate verifies revocation date is valid and returns it
// as a time.Time value. Empty string "" (Not Revoked) is ok.
// It accepts following time format.
//   - UTCTime (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.1)
//   - GeneralizedTime (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.2)
func (e *EntryExchange) VerifyRevDate(target string) (time.Time, error) {
	var date time.Time

	if target == "" {
		return date, nil
	}

	date, ok := e.convASN1DateStrToTime(target)
	if !ok {
		return date, InvalidEntryError{
			attr: "rev_date",
			msg:  target,
		}
	}

	return date, nil
}

// VerifyCRLReason verifies if the CRLReason is correct (case-insensitive).
func (e *EntryExchange) VerifyCRLReason(target string) (EntryCRLReason, error) {
	switch target {
	case "":
		return NotRevoked, nil
	case UnspecifieValue:
		return Unspecified, nil
	case KeyCompromisValue:
		return KeyCompromise, nil
	case CACompromisValue:
		return CACompromise, nil
	case AffiliationChangeValue:
		return AffiliationChanged, nil
	case SupersedeValue:
		return Superseded, nil
	case CessationOfOperatioValue:
		return CessationOfOperation, nil
	case CertificateHolValue:
		return CertificateHold, nil
	case RemoveFromCRValue:
		return RemoveFromCRL, nil
	// Additional pseudo reasons
	case PrivilegeWithdrawValue:
		return PrivilegeWithdrawn, nil
	case AACompromisValue:
		return AACompromise, nil
	}
	return Unspecified, InvalidEntryError{
		attr: "crl_reason",
		msg:  target,
	}
}

// ParseCertificateEntry parses a CertificateEntry from an IntermediateEntry
// using the ParseCertificateEntry.Verify* methods. Set errors from the `Verify*`
// methods to `EntryExchange.Errors` when the entry is invalid.
func (e *EntryExchange) ParseCertificateEntry(
	itmdEntry IntermidiateEntry,
) CertificateEntry {
	verifyErros := make(map[InvalidWith]error, UndefinedCRLReason+1)

	ca := itmdEntry.Ca

	serial, err := e.VerifySerial(itmdEntry.Serial)
	if err != nil {
		verifyErros[MalformSerial] = err
	}

	expDate, err := e.VerifyExpDate(itmdEntry.ExpDate)
	if err != nil {
		verifyErros[MalformExpDate] = err
	}

	revDate, err := e.VerifyRevDate(itmdEntry.RevDate)
	if err != nil {
		verifyErros[MalformRevDate] = err
	}

	crlReason, err := e.VerifyCRLReason(itmdEntry.CRLReason)
	if err != nil {
		verifyErros[UndefinedCRLReason] = err
	}

	revType, err := e.VerifyRevType(itmdEntry.RevType, itmdEntry.RevDate, itmdEntry.CRLReason)
	if err != nil {
		verifyErros[UndefinedRevType] = err
	}

	return CertificateEntry{
		Ca:        ca,
		Serial:    serial,
		RevType:   revType,
		ExpDate:   expDate,
		RevDate:   revDate,
		CRLReason: crlReason,
		Errors:    verifyErros,
	}
}

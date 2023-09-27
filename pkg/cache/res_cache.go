package cache

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

// ResponseCache represents pre-produced OCSP response.
// (https://www.rfc-editor.org/rfc/rfc5019)
type ResponseCache struct {
	entry    db.CertificateEntry
	template ocsp.Response
	response []byte
	sha1Hash []byte
}

// ResponseCacheNotCreatedError is used when the creation of a pre-signed
// response cache from a CertificateEntry fails with errors.
type ResponseCacheNotCreatedError struct {
	reason string
}

func (e ResponseCacheNotCreatedError) Error() string {
	return "pre-signed cache could not be created: " + e.reason
}

func revokedAtFromEntry(entry db.CertificateEntry) time.Time {
	var revokedAt time.Time

	if entry.RevDate.Compare(time.Time{}) != 0 {
		revokedAt = entry.RevDate
	} else {
		revokedAt = entry.ExpDate
	}
	return revokedAt
}

func statusFromEntry(entry db.CertificateEntry) int {
	var status int

	switch entry.RevType {
	case db.Valid:
		status = ocsp.Good
	case db.Revoked:
		status = ocsp.Revoked
	}

	return status
}

// CreatePreSignedResponseCache verifies the CertificateEntry
// and creates a new instance of ResponseCache.
// The new instance of ResponseCache contains an ocsp.Response,
// which is a signed response template.
func CreatePreSignedResponseCache(
	entry db.CertificateEntry, thisUpdate time.Time, interval time.Duration,
) (ResponseCache, error) {
	var resCache ResponseCache

	for i := db.MalformSerial; i <= db.UndefinedCRLReason; i++ {
		_, ok := entry.Errors[i]
		if !ok {
			continue
		}
		return resCache, ResponseCacheNotCreatedError{"entry already contains a previously identified error."}
	}

	var tmpl ocsp.Response

	// SerialNumber
	if entry.Serial == nil {
		return resCache, ResponseCacheNotCreatedError{"entry.Serial is nil."}
	}

	if len(entry.Serial.Text(db.SerialBase)) > db.SerialMaxOctetLength*2 {
		return resCache, ResponseCacheNotCreatedError{"entry.Serial exceeds 20 octets."}
	}
	tmpl.SerialNumber = entry.Serial

	// RevokedAt
	tmpl.RevokedAt = revokedAtFromEntry(entry)

	// Status
	stat := statusFromEntry(entry)
	tmpl.Status = stat

	// RevocationReason
	if entry.CRLReason == db.NotRevoked {
		entry.CRLReason = db.Unspecified
	} else {
		tmpl.RevocationReason = int(entry.CRLReason)
	}

	// ThisUpdate
	tmpl.ThisUpdate = thisUpdate

	// NextUpdate
	tmpl.NextUpdate = thisUpdate.Add(interval)

	return ResponseCache{
		entry:    entry,
		template: tmpl,
		response: nil,
		sha1Hash: nil,
	}, nil
}

// Entry returns a CertificateEntry object.
func (r *ResponseCache) Entry() db.CertificateEntry {
	return r.entry
}

// Template returns the ocsp.Response as template of signed response.
func (r *ResponseCache) Template() ocsp.Response {
	return r.template
}

// SetCertToTemplate sets the provided x509.Certificate as the value
// of the ocsp.Response template member.
func (r *ResponseCache) SetCertToTemplate(cert *x509.Certificate) {
	r.template.Certificate = cert
}

// SetResponse calculates and sets the SHA-1 hash of the provided signed OCSP.
func (r *ResponseCache) SetResponse(response []byte) (*ResponseCache, error) {
	tmp := make([]byte, len(response))
	copy(tmp, response)

	sha1 := sha1.New()
	_, err := sha1.Write(tmp)
	if err != nil {
		return r, err
	}

	r.response = response
	r.sha1Hash = sha1.Sum(nil)

	return r, nil
}

// Response returns a copy of the signed response cache.
func (r *ResponseCache) Response() []byte {
	if r.response == nil {
		return nil
	}
	res := make([]byte, len(r.response))
	copy(res, r.response)
	return res
}

// SHA1Hash returns the copy of the SHA1 hash of the OCSP response.
func (r *ResponseCache) SHA1Hash() []byte {
	if r.sha1Hash == nil {
		return nil
	}
	hash := make([]byte, len(r.sha1Hash))
	copy(hash, r.sha1Hash)
	return hash
}

// Write is a helper method for http.Handler that allows direct writing of
// response bytes without copying them.
func (r *ResponseCache) Write(w http.ResponseWriter) (int, error) {
	return w.Write(r.response)
}

// SHA1HashHexString is a helper method for http.Handler that allows direct
// formatting of the response bytes to a string without copying them.
func (r *ResponseCache) SHA1HashHexString() string {
	return fmt.Sprintf("%x", r.sha1Hash)
}

package dyocsp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/yuxki/dyocsp/pkg/cache"
	"golang.org/x/crypto/ocsp"
)

// KeyFormat is a supported key format type.
type KeyFormat int

const (
	// PKCS #8 key format.
	PKCS8 KeyFormat = iota
	FormatUnknown
)

// KeyAlg is a supported signing key algorithm.
type KeyAlg int

const (
	// RSA signing key algorithm.
	AlgRSA KeyAlg = iota
	// ECDSA signing key algorithm.
	AlgECDSA
	AlgUnknown
)

type pKIResource string

const (
	responderCert = "responder certificate"
	responderKey  = "private Key"
	issuerCert    = "issuer certificate"
)

type invalidPKIResourceError struct {
	resource pKIResource
	reason   string
}

func (e invalidPKIResourceError) Error() string {
	return fmt.Sprintf("invalid %s: %s", e.resource, e.reason)
}

// IssuerHash is used to compare the hashes of the responder's
// issuer and the requested issuer to check if they are the same.
type IssuerHash struct {
	// SHA-1 hash.
	SHA1 []byte
}

func createIssuerSHA1Hash(input []byte) ([]byte, error) {
	cInput := make([]byte, len(input))
	copy(cInput, input)

	sha := sha1.New()

	_, err := io.WriteString(sha, string(cInput))
	if err != nil {
		return nil, err
	}

	return sha.Sum(nil), nil
}

func createIssuerHash(input []byte) (IssuerHash, error) {
	var iHash IssuerHash

	sha1Sum, err := createIssuerSHA1Hash(input)
	if err != nil {
		return iHash, err
	}
	iHash.SHA1 = sha1Sum

	return iHash, nil
}

// AuthorizedType represents the entity that authorizes a responder.
type AuthorizedType int

const (
	// CA signs the response cache directory itself.
	Itself AuthorizedType = iota
	// CA has delegated signing authorization to the responder.
	// The responder's certificate contains the id-kp-OCSPSigning extension.
	Delegation
)

// The Responder struct represents an OCSP responder. It has the ability to sign
// the response cache and verify the issuer in OCSP requests.
type Responder struct {
	rCert      *x509.Certificate
	rPrivKey   crypto.PrivateKey
	rKeyFormat KeyFormat
	rKeyAlg    KeyAlg
	issuerCert *x509.Certificate
	// Hash of issuer's DN
	IssuerNameHash IssuerHash
	// Hash of issuer's public key
	IssuerKeyHash IssuerHash
	// Represents the entity that authorizes a responder.
	AuthType AuthorizedType
}

func detectPrivKeyPemFormat(pem []byte) KeyFormat {
	p8Re := regexp.MustCompile("BEGIN PRIVATE KEY")
	if p8Re.Match(pem) {
		return PKCS8
	}

	return FormatUnknown
}

func parsePKCS8PrivKey(block *pem.Block) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse a PKCS #8, ASN.1 DER private key: %w", err,
		)
	}
	return key, nil
}

func detectPrivKeyAlgorithm(key crypto.PrivateKey) (KeyAlg, bool) {
	_, ok := key.(*rsa.PrivateKey)
	if ok {
		return AlgRSA, true
	}

	_, ok = key.(*ecdsa.PrivateKey)
	if ok {
		return AlgECDSA, true
	}

	return AlgUnknown, false
}

func calculateIssuerHashes(issuer *x509.Certificate) (IssuerHash, IssuerHash, error) {
	var keyHash, nameHash IssuerHash

	sbjPub, err := extractSubjectPublicKey(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return keyHash, nameHash, fmt.Errorf("failed to SubjectPublicKey from SubjectPublicKeyInfo: %w", err)
	}

	keyHash, err = createIssuerHash(sbjPub)
	if err != nil {
		return keyHash, nameHash, err
	}

	nameHash, err = createIssuerHash(issuer.RawSubject)
	if err != nil {
		return keyHash, nameHash, err
	}

	return keyHash, nameHash, nil
}

func detectAuthType(cert *x509.Certificate) AuthorizedType {
	for _, k := range cert.ExtKeyUsage {
		if k == x509.ExtKeyUsageOCSPSigning {
			return Delegation
		}
	}
	return Itself
}

// BuildResponder verifies the provided certificates and private key
// formats. It takes a PEM format responder certificate, a PKCS#8 encoded PEM format
// responder private key, and a PEM format issuer certificate as input. It then creates and
// returns a new dyocsp.Responder instance.
func BuildResponder(rCertPem, rPrivKeyPem, issuerCertPem []byte) (*Responder, error) {
	// Parse Responder Certificate
	rCertblock, _ := pem.Decode(rCertPem)
	rCert, err := x509.ParseCertificate(rCertblock.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse Responder Key
	rKeyFormat := detectPrivKeyPemFormat(rPrivKeyPem)
	keyblock, _ := pem.Decode(rPrivKeyPem)
	var rPrivKey crypto.PrivateKey
	switch rKeyFormat {
	case PKCS8:
		rPrivKey, err = parsePKCS8PrivKey(keyblock)
		if err != nil {
			return nil, err
		}
	case FormatUnknown:
		return nil, invalidPKIResourceError{responderKey, "Found unsupported key format."}
	}

	rKeyAlg, ok := detectPrivKeyAlgorithm(rPrivKey)
	if !ok {
		return nil, invalidPKIResourceError{
			responderKey, "Could not detect singing algorithm from private key.",
		}
	}

	// Parse Issuer Certificate
	iCertblock, _ := pem.Decode(issuerCertPem)
	iCert, err := x509.ParseCertificate(iCertblock.Bytes)
	if err != nil {
		return nil, err
	}

	iKeyHash, iNameHash, err := calculateIssuerHashes(iCert)
	if err != nil {
		return nil, err
	}

	authType := detectAuthType(rCert)

	responder := &Responder{
		rCert:          rCert,
		rPrivKey:       rPrivKey,
		rKeyFormat:     rKeyFormat,
		rKeyAlg:        rKeyAlg,
		issuerCert:     iCert,
		IssuerNameHash: iNameHash,
		IssuerKeyHash:  iKeyHash,
		AuthType:       authType,
	}

	if err := responder.Verify(); err != nil {
		return nil, err
	}

	return responder, nil
}

func (r *Responder) verifyDesignedOCSPSigning() error {
	if r.rCert.IsCA {
		return nil
	}

	for _, k := range r.rCert.ExtKeyUsage {
		if k == x509.ExtKeyUsageOCSPSigning {
			return nil
		}
	}

	return invalidPKIResourceError{
		responderCert,
		"authorized reponder certificate does not include a value of id-kp-OCSPSigning.",
	}
}

func (r *Responder) verifyIssuerSignedResponder() error {
	if !bytes.Equal(r.rCert.AuthorityKeyId, r.issuerCert.SubjectKeyId) {
		return invalidPKIResourceError{
			issuerCert, "keyIdentifier is not matched the responder certificate.",
		}
	}

	err := r.rCert.CheckSignatureFrom(r.issuerCert)
	if err != nil {
		return err
	}

	return nil
}

func (r *Responder) verifyNotExpired() error {
	if r.rCert.NotAfter.Compare(time.Now().UTC()) < 0 {
		return invalidPKIResourceError{responderCert, "date of Not After is past."}
	}

	return nil
}

func (r *Responder) verifyRCertBeforeDateNotFuture() error {
	if time.Now().UTC().Compare(r.rCert.NotBefore) < 0 {
		return invalidPKIResourceError{responderCert, "date of Not Before is future."}
	}

	return nil
}

func (r *Responder) getPrivateKeyAsRSA() (*rsa.PrivateKey, bool) {
	priv, ok := r.rPrivKey.(*rsa.PrivateKey)
	if !ok {
		return nil, false
	}
	return priv, true
}

func (r *Responder) getPrivateKeyAsECDSA() (*ecdsa.PrivateKey, bool) {
	priv, ok := r.rPrivKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, false
	}
	return priv, true
}

func (r *Responder) verifyRKeyRSAPairValid() error {
	priv, ok := r.getPrivateKeyAsRSA()
	if !ok {
		return invalidPKIResourceError{responderKey, "key algorithm has been modified."}
	}

	pub, ok := r.rCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return invalidPKIResourceError{
			responderCert, "algorithm of private key does not matche the public key.",
		}
	}

	if !priv.PublicKey.Equal(pub) {
		return invalidPKIResourceError{responderKey, "private key is not pair of the public key."}
	}
	return nil
}

func (r *Responder) verifyRKeyECDSAPairValid() error {
	priv, ok := r.getPrivateKeyAsECDSA()
	if !ok {
		return invalidPKIResourceError{responderKey, "key algorithm has been modified."}
	}

	pub, ok := r.rCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return invalidPKIResourceError{
			responderCert, "algorithm of private key does not matche the public key.",
		}
	}

	if !priv.PublicKey.Equal(pub) {
		return invalidPKIResourceError{responderKey, "private key is not pair of the public key."}
	}

	return nil
}

// Verify that the responder has valid certificates and a private key.
func (r *Responder) Verify() error {
	err := r.verifyDesignedOCSPSigning()
	if err != nil {
		return err
	}

	err = r.verifyIssuerSignedResponder()
	if err != nil {
		return err
	}

	err = r.verifyNotExpired()
	if err != nil {
		return err
	}

	err = r.verifyRCertBeforeDateNotFuture()
	if err != nil {
		return err
	}

	switch r.rKeyAlg {
	case AlgRSA:
		err = r.verifyRKeyRSAPairValid()
	case AlgECDSA:
		err = r.verifyRKeyECDSAPairValid()
	case AlgUnknown:
		return invalidPKIResourceError{responderKey, "key algorithm has been modified."}
	}
	if err != nil {
		return err
	}

	return nil
}

// SignResponse signs the pre-signed cache.ResponseCache and creates a SHA-1 hash
// from the signed response for caching by the client (e.g., ETag).
// The type of signature algorithm used depends on the specific
// type of private key being used by the responder.
func (r *Responder) SignCacheResponse(cache cache.ResponseCache) (cache.ResponseCache, error) {
	var priv crypto.Signer
	var err error

	var ok bool
	switch {
	case r.rKeyAlg == AlgRSA:
		priv, ok = r.getPrivateKeyAsRSA()
	case r.rKeyAlg == AlgECDSA:
		priv, ok = r.getPrivateKeyAsECDSA()
	}
	if !ok {
		return cache, invalidPKIResourceError{
			responderKey,
			"The private key algorithm has been modified since the configuration was set up.",
		}
	}

	res, err := ocsp.CreateResponse(r.issuerCert, r.rCert, cache.GetTemplate(), priv)
	if err != nil {
		return cache, err
	}

	_, err = cache.SetResponse(res)
	if err != nil {
		return cache, err
	}

	return cache, nil
}

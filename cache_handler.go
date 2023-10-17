package dyocsp

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

const GETMethodMaxRequestSize = 255

func handleHTTPMethod(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
		case http.MethodGet:
			if r.ContentLength > int64(GETMethodMaxRequestSize) {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func handleOverMaxRequestBytes(max int) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if max > 0 {
				if r.ContentLength > int64(max) {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
			}
			h.ServeHTTP(w, r)
		})
	}
}

// CacheHandler is an implementation of the http.Handler interface.
// It is used to handle OCSP requests.
type CacheHandler struct {
	cacheStore *cache.ResponseCacheStoreRO
	responder  *Responder
	// spec       CacheHandlerSpec
	now             date.Now
	maxRequestBytes int
	maxAge          int
	logger          *zerolog.Logger
}

// CacheHandlerOption is type of an functional option for dyocsp.CacheHandler.
type CacheHandlerOption func(*CacheHandler)

// MaxRequestBytes defines the maximum size of a request in bytes. If the content
// of a request exceeds this parameter, the handler will respond with
// http.StatusRequestEntityTooLarge. Default value is 0, and if 0 or less than 0 is
// set, this option is ignored.
func WithMaxRequestBytes(max int) func(*CacheHandler) {
	return func(c *CacheHandler) {
		c.maxRequestBytes = max
	}
}

// MaxAge defines the maximum age, in seconds, for a cached response as
// specified in the Cache-Control max-age directive.
// If the duration until the nextUpdate of a cached response exceeds MaxAge,
// the handler sets the response's Cache-Control max-age directive to that duration.
// Default value is 0. If less than 0 is set, the default value is used.
func WithMaxAge(max int) func(*CacheHandler) {
	return func(c *CacheHandler) {
		c.maxAge = max
	}
}

// WithHandlerLogger sets logger. If not set, global logger is used.
func WithHandlerLogger(logger *zerolog.Logger) func(*CacheHandler) {
	return func(c *CacheHandler) {
		c.logger = logger
	}
}

const (
	DefaultMaxAge = 0
)

// NewCacheHandler creates a new instance of dyocsp.CacheHandler.
// It chains the following handlers before the handler that sends the OCSP response.
// (It uses 'https://github.com/justinas/alice' to chain the handlers.)
//   - Send http.StatusMethodNotAllowed unless the request method is POST or Get.
//   - Send http.StatusRequestEntityTooLarge if the size of the request
//     exceeds the value of the variable spec.MaxRequestBytes..
func NewCacheHandler(
	cacheStore *cache.ResponseCacheStoreRO,
	responder *Responder,
	chain alice.Chain,
	opts ...CacheHandlerOption,
) http.Handler {
	handler := CacheHandler{
		cacheStore: cacheStore,
		responder:  responder,
		now:        date.NowGMT,
	}

	for _, opt := range opts {
		opt(&handler)
	}

	if handler.maxAge < 0 {
		handler.maxAge = DefaultMaxAge
	}

	if handler.logger == nil {
		handler.logger = &log.Logger
	}

	chain = chain.Append(handleHTTPMethod)
	chain = chain.Append(handleOverMaxRequestBytes(handler.maxRequestBytes))

	return chain.Then(handler)
}

type invalidIssuerError struct {
	reason string
}

func (e invalidIssuerError) Error() string {
	return "Invalid issuer in request: " + e.reason
}

func verifyIssuer(req *ocsp.Request, responder *Responder) error {
	// Check issuer is collect
	switch req.HashAlgorithm {
	case crypto.SHA1:
		if !reflect.DeepEqual(req.IssuerNameHash, responder.IssuerNameHash.SHA1) {
			return invalidIssuerError{fmt.Sprintf("IssuerNameHash not matched:%x", req.IssuerNameHash)}
		}
		if !reflect.DeepEqual(req.IssuerKeyHash, responder.IssuerKeyHash.SHA1) {
			return invalidIssuerError{fmt.Sprintf("SubjectPublicKeyHash not matched:%x", req.IssuerKeyHash)}
		}
	default:
		return invalidIssuerError{fmt.Sprintf("Unsupported hash algorithm:%d", req.HashAlgorithm)}
	}

	return nil
}

func addSuccessOCSPResHeader(w http.ResponseWriter, cache *cache.ResponseCache, nowT time.Time, cacheCtlMaxAge int) {
	// Configured max-age cannot be over nextUpdate
	maxAge := cacheCtlMaxAge
	durToNext := cache.Template().NextUpdate.Sub(nowT)
	if durToNext < time.Second*time.Duration(cacheCtlMaxAge) {
		maxAge = int(durToNext / time.Second)
	}

	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d, public, no-transform, must-revalidate", maxAge))
	w.Header().Add("Last-Modified", cache.Template().ProducedAt.Format(http.TimeFormat))
	w.Header().Add("Expires", cache.Template().NextUpdate.Format(http.TimeFormat))
	w.Header().Add("Date", nowT.Format(http.TimeFormat))
	w.Header().Add("ETag", cache.SHA1HashHexString())
}

var ErrUnexpectedHTTPMethod = errors.New("unexpected HTTP method")

// ServeHTTP handles an OCSP request with following  steps.
//   - Verify that the request is in the correct form of an OCSP request.
//     If the request is Malformed, it sends ocsp.MalformedRequestErrorResponse.
//   - Check if the issuer is correct.
//     If the issuer is not valid, it sends ocsp.UnauthorizedErrorRespons.
//   - Searche for a response cache using the serial number from the request.
//     If the cache is not found, it sends ocsp.UnauthorizedErrorRespons.
//
// This Handler add headers Headers introduced in RFC5019.
// (https://www.rfc-editor.org/rfc/rfc5019#section-5)
func (c CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set logger attributes same as access log
	logger := c.logger.With().Str("ip", r.RemoteAddr).Str("user_agent", r.UserAgent()).Logger()

	var body []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		base := strings.TrimPrefix(path.Base(r.URL.Path), "/")
		logger.Debug().Err(err).Str("ocsp-request-path", base).Msg("")
		body, err = base64.StdEncoding.DecodeString(base)
	case http.MethodPost:
		body, err = io.ReadAll(r.Body)
	default:
		err = ErrUnexpectedHTTPMethod
	}
	if err != nil {
		logger.Error().Err(err).Msg("")
		return
	}

	// Handle as OCSP request
	w.Header().Add("Content-Type", "application/ocsp-response")

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		logger.Debug().Err(err).Bytes("ocsp-request-bytes", body).Msg("")
		_, err = w.Write(ocsp.MalformedRequestErrorResponse)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		return
	}

	logger = logger.With().Str("serial", ocspReq.SerialNumber.Text(db.SerialBase)).Logger()
	logger.Debug().Msg("Received OCSP Request.")

	// Check issuer is collect
	err = verifyIssuer(ocspReq, c.responder)
	if err != nil {
		logger.Error().Err(err).Msg("")
		_, err = w.Write(ocsp.UnauthorizedErrorResponse)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		return
	}

	cache, ok := c.cacheStore.Get(ocspReq.SerialNumber)
	if !ok {
		logger.Error().Msgf("Request serial not matched.")
		_, err = w.Write(ocsp.UnauthorizedErrorResponse)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		return
	}

	nowT := c.now()
	if cmp := nowT.Compare(cache.Template().NextUpdate); cmp > 0 {
		logger.Error().Msgf("nextUpdate of found cache is set in the past.")
		_, err = w.Write(ocsp.UnauthorizedErrorResponse)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		return
	}

	addSuccessOCSPResHeader(w, cache, nowT, c.maxAge)
	_, err = cache.Write(w)
	if err != nil {
		logger.Error().Err(err).Msg("")
	}
}

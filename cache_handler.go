package dyocsp

import (
	"crypto"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

// CacheHandlerSpec is required cache handler specification.
type CacheHandlerSpec struct {
	// MaxRequestBytes defines the maximum size of a request in bytes. If the content
	// of a request exceeds this parameter, the handler will respond with
	// http.StatusRequestEntityTooLarge.
	MaxRequestBytes int
	// MaxAge defines the maximum age, in seconds, for a cached response as
	// specified in the Cache-Control max-age directive.
	// If the duration until the nextUpdate of a cached response exceeds MaxAge,
	// the handler sets the response's Cache-Control max-age directive to that duration.
	MaxAge int
	// Logger is specified zerolog.Logger.
	Logger zerolog.Logger
}

func handleNotallowedMethod(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func handleOverMaxRequestBytes(max int) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if max != 0 {
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
	spec       CacheHandlerSpec
	now        date.Now
}

// NewCacheHandler creates a new instance of dyocsp.CacheHandler.
// It chains the following handlers before the handler that sends the OCSP response.
// (It uses 'https://github.com/justinas/alice' to chain the handlers.)
//   - Send http.StatusMethodNotAllowed unless the request method is POST.
//   - Send http.StatusRequestEntityTooLarge if the size of the request
//     exceeds the value of the variable spec.MaxRequestBytes..
func NewCacheHandler(
	cacheStore *cache.ResponseCacheStoreRO,
	responder *Responder,
	spec CacheHandlerSpec,
	chain alice.Chain,
) http.Handler {
	chain = chain.Append(handleNotallowedMethod)
	chain = chain.Append(handleOverMaxRequestBytes(spec.MaxRequestBytes))

	return chain.Then(CacheHandler{
		cacheStore: cacheStore,
		responder:  responder,
		spec:       spec,
		now:        date.NowGMT,
	})
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
	durToNext := cache.GetTemplate().NextUpdate.Sub(nowT)
	if durToNext < time.Second*time.Duration(cacheCtlMaxAge) {
		maxAge = int(durToNext / time.Second)
	}

	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d, public, no-transform, must-revalidate", maxAge))
	w.Header().Add("Last-Modified", cache.GetTemplate().ProducedAt.Format(http.TimeFormat))
	w.Header().Add("Expires", cache.GetTemplate().NextUpdate.Format(http.TimeFormat))
	w.Header().Add("Date", nowT.Format(http.TimeFormat))
	w.Header().Add("ETag", cache.SHA1HashHexString())
}

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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	// Set logger attributes same as access log
	logger := c.spec.Logger.With().Str("ip", r.RemoteAddr).Str("user_agent", r.UserAgent()).Logger()

	// Handle as OCSP request
	w.Header().Add("Content-Type", "application/ocsp-response")

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
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
	if cmp := nowT.Compare(cache.GetTemplate().NextUpdate); cmp > 0 {
		logger.Error().Msgf("nextUpdate of found cache is set in the past.")
		_, err = w.Write(ocsp.UnauthorizedErrorResponse)
		if err != nil {
			logger.Error().Err(err).Msg("")
		}
		return
	}

	addSuccessOCSPResHeader(w, cache, nowT, c.spec.MaxAge)
	_, err = cache.Write(w)
	if err != nil {
		logger.Error().Err(err).Msg("")
	}
}

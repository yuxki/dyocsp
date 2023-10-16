package dyocsp

import (
	"bytes"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	stduri "net/url"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog/log"
	"github.com/yuxki/dyocsp/pkg/cache"
	"github.com/yuxki/dyocsp/pkg/date"
	"github.com/yuxki/dyocsp/pkg/db"
	"golang.org/x/crypto/ocsp"
)

func testCreateServer(t *testing.T, port string, handler http.Handler) (s *http.Server, url string) {
	t.Helper()

	addr := net.JoinHostPort("localhost", port)

	s = &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	url = "http://" + addr

	return s, url
}

func testServerRunning(t *testing.T, url string) {
	// A Port number must no be duplicated between tests
	t.Helper()

	tryN := 20
	for {
		res, err := http.Get(url)
		if err == nil {
			res.Body.Close()
			break
		}
		tryN--
		if tryN <= 0 {
			t.Fatal("Server is not running after health checks.")
		}
		time.Sleep(time.Second * 1)
	}
}

func TestCacheHandler_ServeHTTP_Methods(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewResponseCacheStore()
	responder := testCreateDelegatedResponder(t)
	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	s, url := testCreateServer(t, "8081", handler)

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Printf("Server listening error: %s", err.Error())
		}
	}()

	testServerRunning(t, url)

	methods := []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	}

	client := &http.Client{}
	for _, method := range methods {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()

		code := http.StatusMethodNotAllowed
		if method == http.MethodPost {
			code = http.StatusOK
		}
		if method == http.MethodGet {
			code = http.StatusOK
		}
		if res.StatusCode != code {
			t.Errorf("Method %s Expected status code is %d but got: %d", method, code, res.StatusCode)
		}
	}
}

func TestCacheHandler_ServeHTTP_OverMaxRequestSize(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewResponseCacheStore()
	responder := testCreateDelegatedResponder(t)
	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(1), WithMaxAge(256),
	)

	s, url := testCreateServer(t, "8082", handler)

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Printf("Server listening error: %s", err.Error())
		}
	}()

	testServerRunning(t, url)

	buf := bytes.NewBuffer([]byte{0xFF, 0xFF, 0xFF})
	res, err := http.Post(url, "", buf)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status code is 413 but got: %d", res.StatusCode)
	}
}

func Test_CacheHandler_ServeHTTP_MalformedRequest(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewResponseCacheStore()
	responder := testCreateDelegatedResponder(t)
	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	s, url := testCreateServer(t, "8083", handler)

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Printf("Server listening error: %s", err.Error())
		}
	}()

	testServerRunning(t, url)

	buf := bytes.NewBuffer([]byte{0xFF, 0xFF, 0xFF})
	res, err := http.Post(url, "", buf)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status code is 200 but got: %d", res.StatusCode)
	}

	ocspRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ocspRes, ocsp.MalformedRequestErrorResponse) {
		t.Fatal("Expected Malformed Request Error Response but got different bytes")
	}
}

func testCreateDummyCache(
	t *testing.T, responder *Responder, interval int,
) cache.ResponseCache {
	t.Helper()

	entry := db.CertificateEntry{}
	entry.Ca = "ca"

	serial, ok := new(big.Int).SetString("8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5", db.SerialBase)
	if !ok {
		t.Fatal("String could not be *big.Int.")
	}
	entry.Serial = serial

	entry.RevType = "V"
	entry.ExpDate = time.Date(2033, 8, 9, 12, 33, 17, 0, time.UTC)
	entry.RevDate = time.Time{}
	entry.CRLReason = db.NotRevoked

	thisUpdate := date.NowGMT()

	resCache, _ := cache.CreatePreSignedResponseCache(entry, thisUpdate, time.Second*time.Duration(interval))
	resCache, _ = responder.SignCacheResponse(resCache)

	return resCache
}

func testTextHeader(t *testing.T, key string, header http.Header, resText string) {
	t.Helper()
	if header.Get(key) != resText {
		t.Errorf(
			"Expected %s is %s, but got: %s",
			key,
			resText,
			header.Get(key),
		)
	}
}

func testTimeHeader(t *testing.T, key string, header http.Header, resTime time.Time) {
	t.Helper()
	if header.Get(key) != resTime.Format(http.TimeFormat) {
		t.Errorf(
			"Expected %s is %s, but got: %s",
			key,
			resTime.Format(http.TimeFormat),
			header.Get(key),
		)
	}
}

func testNumberHeader(t *testing.T, key string, header http.Header, resN int) {
	t.Helper()
	if header.Get(key) == strconv.Itoa(resN) {
		t.Errorf(
			"Expected %s is %d, but got: %s",
			key,
			resN,
			header.Get(key),
		)
	}
}

func testHTTPResHeader(t *testing.T, header http.Header, ocspRes *ocsp.Response) {
	t.Helper()

	// RFC5019: content-type: content-type
	testTextHeader(t, "Content-Type", header, "application/ocsp-response")
	testTextHeader(t, "Cache-Control", header, "max-age=256, public, no-transform, must-revalidate")

	// RFC5019:
	// - content-length: <OCSP response length>
	// - cache-control: max-age=<n>, public, no-transform, must-revalidate
	testNumberHeader(t, "Content-Length", header, len(ocspRes.Raw))

	// RFC5019:
	//  - last-modified: <producedAt [HTTP] date>
	//  - expires: <nextUpdate [HTTP] date>
	testTimeHeader(t, "Last-Modified", header, ocspRes.ProducedAt)
	testTimeHeader(t, "Expires", header, ocspRes.NextUpdate)

	// date: <current [HTTP] date>
	if header.Get("Date") == "" {
		t.Error("Date header is not set")
	}

	// RFC5019: ETag: "<strong validator (SHA1 hash of the OCSPResponse structure)>"
	if len(header.Get("ETag")) != 40 {
		t.Errorf("Expoected ETag is SHA1 Hash but got: %s", header.Get("ETag"))
	}
}

func testHTTPResContent(t *testing.T, responder *Responder, res *http.Response, cache cache.ResponseCache) {
	t.Helper()

	rawRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	ocspRes, err := ocsp.ParseResponse(rawRes, responder.rCert)
	if err != nil {
		t.Fatal(err)
	}

	if ocspRes.SerialNumber.Cmp(cache.Template().SerialNumber) != 0 {
		t.Fatal("Cached response is not match with requested response")
	}
}

func testHandlerWithGETMethod(t *testing.T, port string, handler http.Handler, responder *Responder) *http.Response {
	t.Helper()

	s, url := testCreateServer(t, port, handler)

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Printf("Server listening error: %s", err.Error())
		}
	}()

	testServerRunning(t, url)

	var opts *ocsp.RequestOptions
	rawReq, err := ocsp.CreateRequest(responder.rCert, responder.issuerCert, opts)
	if err != nil {
		t.Fatal(err)
	}

	base64Req := base64.StdEncoding.EncodeToString(rawReq)

	url, err = stduri.JoinPath(url, base64Req)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func testHandlerWithPOSTMethod(t *testing.T, port string, handler http.Handler, responder *Responder) *http.Response {
	t.Helper()

	s, url := testCreateServer(t, port, handler)

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			log.Printf("Server listening error: %s", err.Error())
		}
	}()

	testServerRunning(t, url)

	var opts *ocsp.RequestOptions
	rawReq, err := ocsp.CreateRequest(responder.rCert, responder.issuerCert, opts)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(rawReq)
	res, err := http.Post(url, "application/ocsp-request", buf)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func TestCacheHandler_ServeHTTP_GET_ResponseSuccess(t *testing.T) {
	t.Parallel()

	responder := testCreateDelegatedResponder(t)
	resCache := testCreateDummyCache(t, responder, 500)
	cacheStore := cache.NewResponseCacheStore()
	cacheStore.Update([]cache.ResponseCache{resCache})

	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithGETMethod(t, "8090", handler, responder)
	defer res.Body.Close()

	template := resCache.Template()
	testHTTPResHeader(t, res.Header, &template)
	testHTTPResContent(t, responder, res, resCache)
}

func TestCacheHandler_ServeHTTP_POST_ResponseSuccess(t *testing.T) {
	t.Parallel()

	responder := testCreateDelegatedResponder(t)
	resCache := testCreateDummyCache(t, responder, 500)
	cacheStore := cache.NewResponseCacheStore()
	cacheStore.Update([]cache.ResponseCache{resCache})

	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithPOSTMethod(t, "8090", handler, responder)
	defer res.Body.Close()

	template := resCache.Template()
	testHTTPResHeader(t, res.Header, &template)
	testHTTPResContent(t, responder, res, resCache)
}

func TestCacheHandler_ServeHTTP_ResponseFailed_DiffIssuer(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewResponseCacheStore()
	responder := testCreateDelegatedResponder(t)
	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithPOSTMethod(t, "8085", handler, responder)
	defer res.Body.Close()

	ocspRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ocspRes, ocsp.UnauthorizedErrorResponse) {
		t.Fatal("Expected Unauthorized Error Response but got different bytes")
	}
}

func TestCacheHandler_ServeHTTP_ResponseFailed_SerialNotMatched(t *testing.T) {
	t.Parallel()

	cacheStore := cache.NewResponseCacheStore()
	responder := testCreateDelegatedResponder(t)
	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithPOSTMethod(t, "8086", handler, responder)
	defer res.Body.Close()

	ocspRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ocspRes, ocsp.UnauthorizedErrorResponse) {
		t.Fatal("Expected Unauthorized Error Response but got different bytes")
	}
}

func TestCacheHandler_ServeHTTP_NowIsOverNextUpdate(t *testing.T) {
	t.Parallel()

	responder := testCreateDelegatedResponder(t)
	resCache := testCreateDummyCache(t, responder, 0)
	time.Sleep(time.Second * 1) // over nextUpdate
	cacheStore := cache.NewResponseCacheStore()
	cacheStore.Update([]cache.ResponseCache{resCache})

	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithPOSTMethod(t, "8087", handler, responder)
	defer res.Body.Close()

	ocspRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ocspRes, ocsp.UnauthorizedErrorResponse) {
		t.Fatal("Expected Unauthorized Error Response but got different bytes")
	}
}

func TestCacheHandler_ServeHTTP_MaxAgeOverNextUpdate(t *testing.T) {
	t.Parallel()

	interval := 200

	responder := testCreateDelegatedResponder(t)
	resCache := testCreateDummyCache(t, responder, interval)
	time.Sleep(time.Second * 1) // over nextUpdate
	cacheStore := cache.NewResponseCacheStore()
	cacheStore.Update([]cache.ResponseCache{resCache})

	handler := NewCacheHandler(
		cacheStore.NewReadOnlyCacheStore(), responder, alice.New(),
		WithMaxRequestBytes(512), WithMaxAge(256),
	)

	res := testHandlerWithPOSTMethod(t, "8088", handler, responder)
	defer res.Body.Close()

	cc := res.Header.Get("Cache-Control")
	ccSecReg := regexp.MustCompile("[0-9]+")
	maxAgeStr := ccSecReg.FindString(cc)
	maxAge, err := strconv.Atoi(maxAgeStr)
	if err != nil {
		t.Fatal(err)
	}

	if maxAge > interval {
		t.Errorf("max-age must not be over duration to nextUpdate (%d).: %d", interval, maxAge)
	}
}

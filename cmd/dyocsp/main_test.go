package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/config"
	"golang.org/x/crypto/ocsp"
	"gopkg.in/yaml.v3"
)

func testParseCertificate(t *testing.T, file string) *x509.Certificate {
	t.Helper()

	certPem, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	der, _ := pem.Decode(certPem)
	if der == nil {
		t.Fatal("Decode failed: " + file)
	}

	cert, err := x509.ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func testUnmarshalConfigFIle(t *testing.T, file string) config.ConfigYAML {
	t.Helper()

	confFile, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var config config.ConfigYAML
	err = yaml.Unmarshal(confFile, &config)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// nolint paralleltest
// Need to set env
func TestMain_InternalIntegration(t *testing.T) {
	// Prepare Test Data
	file := "testdata/internal-integration.yml"
	yml := testUnmarshalConfigFIle(t, file)

	var cfg config.DyOCSPConfig
	cfg, errs := yml.Verify(cfg)
	if errs != nil {
		t.Fatal("Verification failed: " + file)
	}

	issuer := testParseCertificate(t, cfg.Issuer)
	cert := testParseCertificate(t, cfg.Certificate)

	var opts *ocsp.RequestOptions
	rawReq, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		t.Fatal(err)
	}
	buf := bytes.NewBuffer(rawReq)

	keyPem, err := os.ReadFile("testdata/sub-ocsp-rsa-pkcs8.key")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DYOCSP_PRIVATE_KEY", string(keyPem))
	if err != nil {
		t.Fatal(err)
	}

	// Run Responder Batch & Server
	responder := newResponder(cfg)
	go run(cfg, responder)

	endpoint := "http://localhost:9080"
	tryN := 20
	for {
		res, err := http.Get(endpoint)
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

	// wait for DB updation
	time.Sleep(time.Second * 3)

	res, err := http.Post(endpoint, "application/ocsp-request", buf)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	rawRes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	ocspRes, err := ocsp.ParseResponse(rawRes, issuer)
	if err != nil {
		t.Fatal(err)
	}

	if ocspRes.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("Invald response.")
	}
}

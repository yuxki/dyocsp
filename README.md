# DyOCSP - Flexible DB OCSP Responder
[![Run Tests](https://github.com/yuxki/dyocsp/actions/workflows/test.yaml/badge.svg)](https://github.com/yuxki/dyocsp/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/yuxki/dyocsp/graph/badge.svg?token=Y8QR7WP3L7)](https://codecov.io/gh/yuxki/dyocsp)
[![Go Report Card](https://goreportcard.com/badge/github.com/yuxki/dyocsp)](https://goreportcard.com/report/github.com/yuxki/dyocsp)

## Introduction
DyOCSP is an OCSP responder for private CA, and implementation of [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) and [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019).
The objective is to have a responder with flexible database backend choices.

## Download
- Get the latest binary from [releases](https://github.com/yuxki/dyocsp/releases).
- Or get the sources:
```
git clone https://github.com/yuxki/dyocsp
```
Please try [Demo](#Demo) after download.


## Supported Environments
#### Database
- [File](docs/fileasdb.md)
- [DynamoDB](docs/dynamodb.md)

#### Protocol
- HTTP (POST Method Only)

#### Signing Key Format
- PKCS# 8

## Full Documentation
Documentation is available here: [manual](docs/index.md)

## Demo
### Start OCSP Responder Server
Build and run `dyocsp` with a demo configuration file, certificate, and key.
```bash
$ cd ./demo
$ go build ../cmd/dyocsp
$ ./dyocsp -c delegate-dyocsp.yml
```

### Test OCSP Request
Open another terminal.
```bash
# Request "successful good" certificate
$ cd demo
$ openssl ocsp \
    -CAfile ca/root-ca.crt \
    -issuer ca/sub-ca.crt \
    -cert ca/good.crt \
    -no_nonce \
    -url http://localhost:9080
```
```bash
# Request "successful revoked" certificate
$ cd ./demo
$ openssl ocsp \
    -CAfile ca/root-ca.crt \
    -issuer ca/sub-ca.crt \
    -cert ca/revoked.crt \
    -no_nonce \
    -url http://localhost:9080
```

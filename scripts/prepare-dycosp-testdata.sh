#!/bin/bash

set -x

OUT_DIR="dyocsp/testdata"
TMP_DIR="./tmp-$$"

mkdir -p "$TMP_DIR"

./scripts/gen-certs.sh "$TMP_DIR"

cp $TMP_DIR/sub-ca/sub-ca.crt $OUT_DIR/sub-ca-rsa.crt

cp $TMP_DIR/sub-ca/private/sub-ca.key $OUT_DIR/sub-ca-rsa-pkcs8.key

cp $TMP_DIR/root-ca/root-ca.crt $OUT_DIR/root-ca-rsa.crt

cp $TMP_DIR/sub-ca/sub-ocsp.crt $OUT_DIR/sub-ocsp-rsa.crt

cp $TMP_DIR/sub-ca/private/sub-ocsp.key $OUT_DIR/sub-ocsp-rsa-pkcs8.key

openssl rsa -text -in tmp/testhome/sub-ca/private/sub-ca.key 2> /dev/null \
  | sed -n '/-----BEGIN RSA PRIVATE KEY-----/,/-----END RSA PRIVATE KEY-----/{ p }' \
    > $OUT_DIR/sub-ocsp-rsa-pkcs1.key

cp $TMP_DIR/sub-ca/sub-ocsp-ecparam.crt $OUT_DIR/sub-ocsp-ecparam.crt

openssl pkcs8 -in $TMP_DIR/sub-ca/private/sub-ocsp-ecparam.key \
  -topk8 -nocrypt -out $OUT_DIR/sub-ocsp-ecparam-pkcs8.key

cp $TMP_DIR/sub-ca/good.crt $OUT_DIR/sub-no-ocsp-rsa.crt

cp $TMP_DIR/sub-ca/good.key $OUT_DIR/sub-no-ocsp-rsa-pkcs8.key

cp $TMP_DIR/sub-ca/sub-expired-ocsp.crt $OUT_DIR/sub-expired-ocsp-rsa.crt
cp $TMP_DIR/sub-ca/private/sub-expired-ocsp.key $OUT_DIR/sub-expired-ocsp-rsa-pkcs8.key

cp $TMP_DIR/sub-ca/sub-future-ocsp.crt $OUT_DIR/sub-future-ocsp-rsa.crt
cp $TMP_DIR/sub-ca/private/sub-future-ocsp.key $OUT_DIR/sub-future-ocsp-rsa-pkcs8.key

cp $TMP_DIR/sub-ca/self-ecparam.crt $OUT_DIR/self-ecparam.crt
cp $TMP_DIR/sub-ca/private/self-ecparam.key $OUT_DIR/self-ecparam.key

rm -rf ${TMP_DIR:?}

set +x

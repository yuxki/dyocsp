#!/bin/bash

set +x

RESPONDER_URL="http://dyocsp"
RESULTS_DIR="./tmp-test-results"
mkdir -p "$RESULTS_DIR"
TABLE_NAME="test_ca_db"
SUB_CA_NAME="sub-ca"
FIXED_SERIAL=""
DYANAMO_DB_URL="http://dynamodb-local:8000"
TEMP_CAS_HOME="tmp-cas"
TEMP_CA_HOME="$TEMP_CAS_HOME/sub-ca"
TEMP_ISSUER_CA_HOME="$TEMP_CAS_HOME/root-ca"
WAIT_ROTATE_TIME=10

set_fixed_serial() {
  local subscriber_name="$1"
  FIXED_SERIAL="$(
    echo "$subscriber_name" \
      | sha1sum \
      | grep -oE "^[0-9a-f]+" \
      | tr '[:lower:]' '[:upper:]'
  )"
  echo "Fixed: ${FIXED_SERIAL}"
}

delete_item() {
  aws dynamodb delete-item --table "$TABLE_NAME" \
    --key "{\"ca\": {\"S\": \"${SUB_CA_NAME}\"},\"serial\": {\"S\": \"${FIXED_SERIAL}\"}}" \
    --endpoint-url "$DYANAMO_DB_URL"
}

revoke_certificate() {
  local crl_reason="$1"
  aws dynamodb update-item --table "$TABLE_NAME" \
    --key "{\"ca\": {\"S\": \"${SUB_CA_NAME}\"},\"serial\": {\"S\": \"${FIXED_SERIAL}\"}}" \
    --update-expression "SET rev_type = :t, rev_date = :r, crl_reason = :c" \
    --expression-attribute-values "{\":t\": {\"S\": \"R\"},\":r\": {\"S\": \"$(date +%y%m%d%I%M%SZ)\"},\":c\": {\"S\": \"${crl_reason}\"}}" \
    --endpoint-url "$DYANAMO_DB_URL"
}

restore_certificate() {
  aws dynamodb update-item --table "$TABLE_NAME" \
    --key "{\"ca\": {\"S\": \"${SUB_CA_NAME}\"},\"serial\": {\"S\": \"${FIXED_SERIAL}\"}}" \
    --update-expression "SET rev_type = :t, rev_date = :r, crl_reason = :c" \
    --expression-attribute-values "{\":t\": {\"S\": \"V\"},\":r\": {\"S\": \"$(date +%y%m%d%I%M%SZ)\"},\":c\": {\"S\": \"${crl_reason}\"}}" \
    --endpoint-url "$DYANAMO_DB_URL"
}

prepare_test_data() {
  aws configure set region us-west-2
  aws configure set aws_access_key_id dummyaccesskey
  aws configure set aws_secret_access_key dummysecretkey

  scripts/index2batch-items.sh \
    test_ca_db \
    root-ca \
    ${TEMP_CAS_HOME}/root-ca/db/index \
    > root-ca-item.json

  ./scripts/index2batch-items.sh \
    test_ca_db \
    sub-ca \
    ${TEMP_CAS_HOME}//sub-ca/db/index \
    > sub-ca-item.json

  ./create-table.sh
  ./batch-write-item.sh
}

echo_test_case() {
  echo "[TEST] $1"
}

TEST_FAILED=0
test_failed() {
  echo "Failed"
  TEST_FAILED=1
}

# Prepare Test ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
prepare_test_data
# Start Test ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# successful pattern ------------------------------------------------------------------------------
sleep $WAIT_ROTATE_TIME # wait for rotating cache
set +e

echo_test_case "good status pattern"
openssl ocsp -issuer "$TEMP_CA_HOME/sub-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/good.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/good.log
if ! grep -q -F "good.crt: good" $RESULTS_DIR/good.log; then
  test_failed
  cat $RESULTS_DIR/good.log
fi
if ! grep -q -F "This Update:" $RESULTS_DIR/good.log; then
  test_failed
  cat $RESULTS_DIR/good.log
fi
if ! grep -q -F "Next Update:" $RESULTS_DIR/good.log; then
  test_failed
  cat $RESULTS_DIR/good.log
fi

echo_test_case "revoked status pattern"
openssl ocsp -issuer "$TEMP_CA_HOME/sub-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/revoked.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/revoked.log
if ! grep -q -F "revoked.crt: revoked" $RESULTS_DIR/revoked.log; then
  test_failed
  cat $RESULTS_DIR/revoked.log
fi
if ! grep -q -F "This Update:" $RESULTS_DIR/revoked.log; then
  test_failed
  cat $RESULTS_DIR/revoked.log
fi
if ! grep -q -F "Next Update:" $RESULTS_DIR/revoked.log; then
  test_failed
  cat $RESULTS_DIR/revoked.log
fi

echo_test_case "two certificate request (response only first cert) situation"
openssl ocsp -issuer "$TEMP_CA_HOME/sub-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/good.crt" -cert "$TEMP_CA_HOME/revoked.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/two-certificate.log
if ! grep -q -F "good.crt: good" $RESULTS_DIR/two-certificate.log; then
  test_failed
  cat $RESULTS_DIR/two-certificate.log
fi
if ! grep -q -F "This Update:" $RESULTS_DIR/two-certificate.log; then
  test_failed
  cat $RESULTS_DIR/two-certificate.log
fi
if ! grep -q -F "Next Update:" $RESULTS_DIR/two-certificate.log; then
  test_failed
  cat $RESULTS_DIR/two-certificate.log
fi
if ! grep -q -F "revoked.crt: ERROR: No Status found." $RESULTS_DIR/two-certificate.log; then
  test_failed
  cat $RESULTS_DIR/two-certificate.log
fi

echo_test_case "Revoke a certificate for keyCompromise situation"
set_fixed_serial "keyCompromise"   # Set fixed serial
revoke_certificate "keyCompromise" # Revoke certificate
sleep $WAIT_ROTATE_TIME            # wait for rotating cache
openssl ocsp -issuer "$TEMP_CA_HOME/sub-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/keyCompromise.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/keyCompromise.log
if ! grep -q -F "keyCompromise.crt: revoked" $RESULTS_DIR/keyCompromise.log; then
  test_failed
  cat $RESULTS_DIR/keyCompromise.log
fi
if ! grep -q -F "This Update:" $RESULTS_DIR/keyCompromise.log; then
  test_failed
  cat $RESULTS_DIR/keyCompromise.log
fi
if ! grep -q -F "Next Update:" $RESULTS_DIR/keyCompromise.log; then
  test_failed
  cat $RESULTS_DIR/keyCompromise.log
fi

# Error pattern -----------------------------------------------------------------------------------
set +e
echo_test_case "unauthorized error pattern (Invalid issuer)"
openssl ocsp -issuer "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/good.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/unauthorized.log
if ! grep -q -F "Responder Error: unauthorized (6)" $RESULTS_DIR/unauthorized.log; then
  test_failed
  cat $RESULTS_DIR/unauthorized.log
fi

echo_test_case "unauthorized error pattern (Subject is not exist)"
set_fixed_serial "unknown" # Set fixed serial
delete_item                # Delete item
sleep $WAIT_ROTATE_TIME    # wait for rotating cache
openssl ocsp -issuer "$TEMP_CA_HOME/sub-ca.crt" \
  -CAfile "$TEMP_ISSUER_CA_HOME/root-ca.crt" \
  -cert "$TEMP_CA_HOME/unknown.crt" \
  -url "$RESPONDER_URL" \
  > $RESULTS_DIR/unknown.log
if ! grep -q -F "Responder Error: unauthorized (6)" $RESULTS_DIR/unknown.log; then
  test_failed
  cat $RESULTS_DIR/unknown.log
fi

echo_test_case "Test malformedRequest error pattern"
curl --silent "$RESPONDER_URL" \
  > $RESULTS_DIR/malformed-request.log
if grep -q -F "Responder Error: malformedRequest (1)" $RESULTS_DIR/malformed-request.log; then
  test_failed
  cat $RESULTS_DIR/malformed-request.log
fi
# END Test ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if [ "$TEST_FAILED" = "0" ]; then
  exit 0
  echo "All test success!!"
fi
exit 1

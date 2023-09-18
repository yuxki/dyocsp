#!/bin/bash

set -e

clean_home() {
  local ca_home="$1"
  rm -fr "$ca_home/certs" "$ca_home/db" "$ca_home/private"
  rm -rf "$ca_home/*.csr" "$ca_home/*.crt" "$ca_home/*.key"
}

init_ca_home() {
  local ca_home="$1"
  local initial_serial="$2"

  mkdir -p "$ca_home/certs" "$ca_home/db" "$ca_home/private"
  touch "${ca_home}/db/index"
  echo "$initial_serial" > "${ca_home}/db/serial"
  echo 1001 > "${ca_home}/db/crlnumber"
}

export_ca_config_envs() {
  export DUMMY_ROOT_CA_HOME="$ROOT_CA_HOME"
  export DUMMY_SUB_CA_HOME="$SUB_CA_HOME"

  export DUMMY_ROOT_CA="Root CA"
  export DUMMY_SUB_CA="Sub CA"

  export DUMMY_OCSP_ROOT_CN="OCSP Sub Responder"
  export DUMMY_OCSP_SUB_CN="OCSP Sub Responder"

  export DUMMY_C="US"
  export DUMMY_O="Example Organization"
  export DUMMY_SERVER_NAME="Server"
}

sign_root_ca() {
  echo -e "\nSigning Root CA..."

  openssl req \
    -newkey rsa:2048 -config "$ROOT_CA_CONF" \
    -out "${ROOT_CA_HOME}/root-ca.csr" \
    -keyout "${ROOT_CA_HOME}/private/root-ca.key"

  openssl ca \
    -batch \
    -config "$ROOT_CA_CONF" \
    -selfsign \
    -in "${ROOT_CA_HOME}/root-ca.csr" \
    -out "${ROOT_CA_HOME}/root-ca.crt" \
    -extensions ca_ext
}

sign_sub_ca() {
  echo -e "\nSigning Sub CA..."

  openssl req \
    -newkey rsa:2048 \
    -config "$SUB_CA_CONF" \
    -out "${SUB_CA_HOME}/sub-ca.csr" \
    -keyout "${SUB_CA_HOME}/private/sub-ca.key"

  openssl ca \
    -batch \
    -config "$ROOT_CA_CONF" \
    -in "${SUB_CA_HOME}/sub-ca.csr" \
    -out "${SUB_CA_HOME}/sub-ca.crt" \
    -extensions sub_ca_ext
}

sign_ocsp_responder_by_root_ca() {
  echo -e "\nSigning OCSP Responder by Root CA..."

  openssl req -new \
    -newkey rsa:2048 \
    -subj "/C=${DUMMY_C}/O=${DUMMY_O}/CN=Root CA OCSP Responder" \
    -keyout "${ROOT_CA_HOME}/private/root-ocsp.key" \
    -nodes \
    -out "${ROOT_CA_HOME}/root-ocsp.csr"

  openssl ca \
    -batch \
    -config "$ROOT_CA_CONF" \
    -in "${ROOT_CA_HOME}/root-ocsp.csr" \
    -out "${ROOT_CA_HOME}/root-ocsp.crt" \
    -extensions ocsp_ext \
    -days 30
}

sign_ocsp_responder_by_sub_ca() {
  echo -e "\nSigning OCSP Responder by Sub CA..."

  openssl req -new \
    -newkey rsa:2048 \
    -subj "/C=${DUMMY_C}/O=${DUMMY_O}/CN=Sub CA OCSP Responder" \
    -keyout "${SUB_CA_HOME}/private/sub-ocsp.key" \
    -nodes \
    -out "${SUB_CA_HOME}/sub-ocsp.csr"

  openssl ca \
    -batch \
    -config "$SUB_CA_CONF" \
    -in "${SUB_CA_HOME}/sub-ocsp.csr" \
    -out "${SUB_CA_HOME}/sub-ocsp.crt" \
    -extensions ocsp_ext \
    -days 30
}

extra_ecparam_sign_ocsp_responder_by_sub_ca() {
  echo -e "\nSigning OCSP Responder by Sub CA..."

  openssl ecparam -genkey -name secp384r1 \
    -out "${SUB_CA_HOME}/private/sub-ocsp-ecparam.key"

  openssl req \
    -new \
    -key "${SUB_CA_HOME}/private/sub-ocsp-ecparam.key" \
    -config "$SUB_CA_CONF" \
    -out "${SUB_CA_HOME}/sub-ocsp-ecparam.csr"

  openssl ca \
    -batch \
    -config "$SUB_CA_CONF" \
    -in "${SUB_CA_HOME}/sub-ocsp-ecparam.csr" \
    -out "${SUB_CA_HOME}/sub-ocsp-ecparam.crt" \
    -extensions ocsp_ext \
    -days 30
}

extra_sign_expired_ocsp_responder_by_sub_ca() {
  echo -e "\nSigning OCSP Responder by Sub CA..."

  openssl req -new \
    -newkey rsa:2048 \
    -subj "/C=${DUMMY_C}/O=${DUMMY_O}/CN=Sub CA Expired OCSP Responder" \
    -keyout "${SUB_CA_HOME}/private/sub-expired-ocsp.key" \
    -nodes \
    -out "${SUB_CA_HOME}/sub-expired-ocsp.csr"

  openssl ca \
    -batch \
    -config "$SUB_CA_CONF" \
    -in "${SUB_CA_HOME}/sub-expired-ocsp.csr" \
    -out "${SUB_CA_HOME}/sub-expired-ocsp.crt" \
    -extensions ocsp_ext \
    --enddate 19000914235323Z
}

extra_sign_future_ocsp_responder_by_sub_ca() {
  echo -e "\nSigning OCSP Responder by Sub CA..."

  openssl req -new \
    -newkey rsa:2048 \
    -subj "/C=${DUMMY_C}/O=${DUMMY_O}/CN=Sub CA Future OCSP Responder" \
    -keyout "${SUB_CA_HOME}/private/sub-future-ocsp.key" \
    -nodes \
    -out "${SUB_CA_HOME}/sub-future-ocsp.csr"

  openssl ca \
    -batch \
    -config "$SUB_CA_CONF" \
    -in "${SUB_CA_HOME}/sub-future-ocsp.csr" \
    -out "${SUB_CA_HOME}/sub-future-ocsp.crt" \
    -extensions ocsp_ext \
    --startdate 20500914235323Z
}

sign_subscriber_by_sub_ca() {
  local subscriber_name="$1"
  echo "Create Subscriber By Sub CA: $subscriber_name"

  export DUMMY_SERVER_NAME="$subscriber_name" # Override

  openssl req \
    -newkey rsa:2048 \
    -config "$SUBSCIRBER_CONF" \
    -out "${SUB_CA_HOME}/${subscriber_name}.csr" \
    -keyout "${SUB_CA_HOME}/${subscriber_name}.key"

  # Fix Serial with SHA1
  echo "$subscriber_name" \
    | sha1sum \
    | grep -oE "^[0-9a-f]+" \
    | tr '[:lower:]' '[:upper:]' \
      > "${SUB_CA_HOME}/db/serial"

  openssl ca \
    -batch \
    -config "$SUB_CA_CONF" \
    -in "${SUB_CA_HOME}/${subscriber_name}.csr" \
    -out "${SUB_CA_HOME}/${subscriber_name}.crt" \
    -extensions server_ext

  export_ca_config_envs # Reset Envs
}

sign_subscriber_by_root_ca() {
  local subscriber_name="$1"
  echo "Create Subscriber By Root CA: $subscriber_name"

  export DUMMY_SERVER_NAME="$subscriber_name" # Override

  openssl req \
    -newkey rsa:2048 \
    -config "$SUBSCIRBER_CONF" \
    -out "${ROOT_CA_HOME}/${subscriber_name}.csr" \
    -keyout "${ROOT_CA_HOME}/${subscriber_name}.key"

  # Fix Serial with SHA1
  echo "$subscriber_name" \
    | sha1sum \
    | grep -oE "^[0-9a-f]+" \
    | tr '[:lower:]' '[:upper:]' \
      > "${SUB_CA_HOME}/db/serial"

  openssl ca \
    -batch \
    -config "$ROOT_CA_CONF" \
    -in "${ROOT_CA_HOME}/${subscriber_name}.csr" \
    -out "${ROOT_CA_HOME}/${subscriber_name}.crt" \
    -extensions server_ext

  export_ca_config_envs # Reset Envs
}

extra_sign_self_sub_ca_with_ecparam() {
  echo -e "\nSigning Self CA wit ECDSA..."

  openssl ecparam -genkey -name secp384r1 \
    -out "${SUB_CA_HOME}/private/self-ecparam-openssl.key"

  openssl pkcs8 \
    -in "${SUB_CA_HOME}/private/self-ecparam-openssl.key" \
    -nocrypt \
    -topk8 \
    -out "${SUB_CA_HOME}/private/self-ecparam.key"

  openssl req -x509 \
    -key "${SUB_CA_HOME}/private/self-ecparam.key" \
    -out "${SUB_CA_HOME}/self-ecparam.crt" \
    -subj '/CN=localhost' \
    -days 3650
}

main() {

  # set shell environments
  SCRIPT_DIR="$(dirname "$0")"
  CONFS_DIR="${SCRIPT_DIR}/gen-certs-confs"
  ROOT_CA_CONF="${CONFS_DIR}/root-ca.conf"
  SUB_CA_CONF="${CONFS_DIR}/sub-ca.conf"
  SUBSCIRBER_CONF="${CONFS_DIR}/server.conf"

  if [ "$#" != "1" ]; then
    echo "Usage: $0 <target_dir>"
    exit 1
  fi

  if [ ! -d "$1" ]; then
    echo "<target_dir> "$1" is not exist, or is not directory."
    exit 1
  fi

  TARGET_DIR="$1"
  ROOT_CA_HOME="${TARGET_DIR}/root-ca"
  SUB_CA_HOME="${TARGET_DIR}/sub-ca"

  clean_home "$ROOT_CA_HOME"
  clean_home "$SUB_CA_HOME"

  init_ca_home "$ROOT_CA_HOME" "1ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5"
  init_ca_home "$SUB_CA_HOME" "8ca7b3fe5d7f007673c18ccc6a1f818085cdc5f5"

  export_ca_config_envs

  # Sign CAs
  sign_root_ca
  sign_sub_ca

  # Sign Delegated OCSP Responder Certificates
  sign_ocsp_responder_by_root_ca
  sign_ocsp_responder_by_sub_ca
  extra_ecparam_sign_ocsp_responder_by_sub_ca
  extra_sign_expired_ocsp_responder_by_sub_ca
  extra_sign_future_ocsp_responder_by_sub_ca

  # Sign Subscriber Certificates
  sign_subscriber_by_sub_ca "good"
  sign_subscriber_by_sub_ca "revoked"
  tail -n 1 "${SUB_CA_HOME}/db/index" | grep -o -P '[0-9A-F]{38,40}'
  openssl ca \
    -config "$SUB_CA_CONF" \
    -revoke "${SUB_CA_HOME}/certs/$(tail -n 1 "${SUB_CA_HOME}/db/index" \
      | grep -o -P '[0-9A-F]{38,40}').pem" \
    -crl_reason "unspecified"
  sign_subscriber_by_sub_ca "unknown"

  sign_subscriber_by_root_ca "unauthorized"
  sign_subscriber_by_sub_ca "keyCompromise"
  sign_subscriber_by_sub_ca "certificateHold"

  extra_sign_self_sub_ca_with_ecparam
}

main "$@"

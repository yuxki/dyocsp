# Usage of File as DB

## Record Format
The DB file format is based on the index file of [github.com/openssl/openssl]('https://github.com/openssl/openssl').
Then, the DB File is in tab-delimited format, and "Revoked Date" and "CRL
 Reason" are in comma-delimited format.
Prease refer [overview](overview.md) documentation for details about certificate revocation data in DyOCSP.
#### Columns and Example data
|Revocation Status|Expired Date|Revoked Date,CRL Reason|Serial Number|
| ----------- | ----------- | ----------- | ----------- |
|V|231012064725Z|""(empty) or 230912064725Z,unspecified|51AFE53E114F3F0D53CD2|

#### Example Contents
```
V\t231012064725Z\t\t8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5
R\t330909064725Z\t230912064725Z,unspecified\t51AFE53E114F3F0D53CD2D19F0E021BEFA3A7B97
```

# Basic Usage
## Create Records from Certificate
Now you have a valid certificate as shown below. The certificate contains the
 local DyOCSP server address in the "Authority Information Access".
```pem
-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIRAMlxjbANYP+VoiqGiu9zV+swDQYJKoZIhvcNAQELBQAw
ADAeFw0yMzA5MTUwMTA5MDdaFw0zMzA5MTIwMTA5MDdaMBkxFzAVBgNVBAgMDkV4
YW1wbGUgU2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr1jH
ZPXQwmInM+Z504gW7zM552wDlF2OQngxY7qv07CfOCuwL01bPoh8bDrUdqpLCky3
H9cYXIb+K0Eqr/1sBayV6w+T+wOXdN3uV6Xra2AvXvMmeLytFw2mQQexUMtbePzi
YWmc+1qQlJMtIDgYsnqXC1AgR8IILOT9jeXAu3eWYx5odrJ0ZhZAKQX8fm/dzYYN
g9tY9Ma7u2VAbEdH2Rq6ca3whw0ZYIJZZ6rLb+r5/z9oOXMWip3erSlVvD0qpVpz
IEjme6EQ0CT6gNDQqnlAHQlY3ShlsZK9u5beVFRt465zVxlrbzSpsz09uvfqJu40
GNPBTaRPZikryg33eQIDAQABo4GEMIGBMDEGCCsGAQUFBwEBBCUwIzAhBggrBgEF
BQcwAYYVaHR0cDovL2xvY2FsaG9zdDo5MDgwMB8GA1UdIwQYMBaAFN0910ymr+d4
sT6QCHnzwsBKI1klMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG
CCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4IBAQBBbaLZVlVXpy+74sw/iXlySRn4
COFj67I4qa8Lo0GuJHQgLhWANL/KF8DJs9OI98ZxSJHFdMQ7dtQg1J+F7ZuzMuKx
R0QbGefa3XrWRzqZ99ITFK8esmLa4MDUU9vHttO3CgqqkZJVR0APhIvc+fgzzYXL
SFlYLbiKOHiLT2vNJE8EuWt1dtPGDv5Yb7g6uwK9smma/bEAYsqMscYEaOyFiuw0
ZsklWHz+t87XR3ZINlhErDHnNrUszdv/tTZ/Ya/X8oBtVlhqz+25rKhxT1Jn3bDi
Sb63QRuOoehTZN8eYMKktLnUzjLnIZjGOxyR1dietxwIdLtsV9OJ3yISnK0k
-----END CERTIFICATE-----
```

#### Create a "Valid Status" Record
1. Get serial from certificate
```
$ export SERIAL="$(openssl x509 -in server.crt -noout -serial | grep -oP '(?<=)[a-fA-F0-9]+$')"
```
2. Get "Not After" from certificate and convert that
```
$ export NOT_AFTER="$(openssl x509 -in server.crt -noout -enddate | grep -oP '(?<==).*(?=GMT)')"
```
3. Format to [GeneralizedTime](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.2)
```
$ export EXP_DATE="$(date -d"${NOT_AFTER}" +%Y%m%d%H%M%SZ)"
```
4. Create record
```
$ echo "V\t${EXP_DATE}\t\t${SERIAL}" >> dbfile
```

#### Update to "Revoked Status"
1. Update status with specifying serial number
```
sed -i '/C9718DB00D60FF95A22A868AEF7357EB/{s/^V/R/}' dbfile
```
2. Update "Revoked Date" and "CRL Reason"
```
sed -i '/C9718DB00D60FF95A22A868AEF7357EB/{s/\t\t/\t20231012010907Z,unspecified\t/}' dbfile
```

## Create Records by `openssl ca` Command
#### Create Private CA
Create private CA.
This section use the below configuration for example.
__You should create a configuration that meets your specific security requirements.__
```
# example-ca.conf
[default]
name          = example-ca
ocsp_url      = http://localhost:9080
default_ca    = default_ca

[default_ca]
home             = .
database         = $home/db/index
serial           = $home/db/serial
certificate      = $home/$name.crt
private_key      = $home/private/$name.key
RANDFILE         = $home/private/random
new_certs_dir    = $home/certs
unique_subject   = no
copy_extensions  = none
default_days     = 3650
default_crl_days = 3650
default_md       = sha256
policy           = policy

[policy]
stateOrProvinceName    = optional
organizationalUnitName = optional
emailAddress           = optional

[req_distinguished_name]
countryName      = "US"
organizationName = "Example"
commonName       = "Example CA"

[req]
encrypt_key         = no
utf8                = yes
string_mask         = utf8only
prompt              = no
distinguished_name  = req_distinguished_name
req_extensions      = ca_extension

[ca_extension]
basicConstraints     = critical,CA:true
keyUsage             = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[issuer_info]
OCSP;URI.0 = $ocsp_url

[server_ext]
authorityInfoAccess    = @issuer_info
authorityKeyIdentifier = keyid:always
basicConstraints       = critical,CA:false
extendedKeyUsage       = clientAuth,serverAuth

[ocsp_extension]
authorityKeyIdentifier = keyid:always
basicConstraints       = critical,CA:false
extendedKeyUsage       = OCSPSigning
keyUsage               = critical,digitalSignature
subjectKeyIdentifier   = hash
```

##### 1. Create Example CA Directory
```bash
$ mkdir example-ca
$ cd example-ca
$ mkdir certs db private
$ chmod 700 private
$ touch db/index
$ openssl rand -hex 16 > db/serial

$ touch example-ca.conf
$ vim example-ca.conf # Edit configuration with any editor
```

##### 2. Sign Self CA
1. Create CSR for the example CA.
```
openssl req -new -config example-ca.conf -out example-ca.csr -keyout private/example-ca.key
```
2. And Sign self.
```
openssl ca -selfsign -config example-ca.conf -in example-ca.csr -out example-ca.crt -extensions ca_extension
```

##### 3. Create & Sign Server Certificate
1. Create CSR for a server.
```
openssl req -new -out server.csr -keyout private/server.key -nodes
```
2. Sign Certificate
```
openssl ca -config example-ca.conf -in server.csr -out server.crt -extensions server_extension
```
Now you can use db/index as DB for also DyOCSP.

##### 4. Create & Sign OCSP Server Certificate
Delegate signing OCSP response to a new OCSP responder.
1. Create CSR for a OCSP responder.
```
openssl req -new -newkey rsa:2048 -keyout "private/ocsp.key" -nodes -out ocsp.csr
```
2. Sign Certificate
```
openssl ca -config example-ca.conf -in "ocsp.csr" -out "ocsp.crt" -extensions ocsp_extension -days 30
```

##### 5. Create DyOCSP Configuration
1. Create dyocsp.yml as DyOCSP Configuration.
```
version: 0.1
log:
  level: "info"
  format: "pretty"
responder:
  ca: "example" # Not used, but required
  responder_certificate: "ocsp.crt"
  responder_key: "private/ocsp.key"
  issuer_certificate: "example-ca.crt"
cache:
  interval: 10
  delay: 2
db:
  file:
    file: "db/index"
http:
  addr: "localhost"
  port: 9080
```

Now, you can test DyOCSP Responder.
```
dyocsp -c dyocsp.yml
```
```
openssl ocsp -CAfile example-ca.crt -issuer example-ca.crt -cert server.crt -no_nonce -url http://localhost:9080
```

# Configuring an OCSP Responder
The following YAML format configuration includes all the configurations for `dycosp`.
## List of configuration options
```yaml
version: 0.1
strict: false
expiration: "ignore"
log:
  level: "info"
  format: "json"
responder:
  ca: "sub-ca"
  responder_certificate: "dyocsp/testdata/sub-ocsp-rsa.crt"
  responder_key: "dyocsp/testdata/sub-ocsp-rsa-pkcs8.key"
  issuer_certificate: "dyocsp/testdata/sub-ca-rsa.crt"
cache:
  interval: 60
  delay: 5
db:
  dynamodb:
    region: "us-west-2"
    table_name: "test_ca_db"
    ca_gsi: "ca_gsi"
    endpoint: ""
    retry_max_attempts: 0
    timeout: 60
  file:
    file: "testdata/filedb"
http:
  addr: ""
  port: 80
  read_timeout: 30
  write_timeout: 0
  read_header_timeout: 10
  max_header_bytes: 1048576 1M
  max_request_bytes: 256
  cache_control_max_age: 60 (same as cache.interval)
```
## version
```yaml
version: 0.1
```
The `version` option is a __required__ field that specifies the configuration version.

## strict
```yaml
strict: false
```
The `strict` option is an __optional (default: false)__ field that enables strict mode.
When strict mode is enabled, if the DB client encounters an error, the `dyocsp` server should stop with a panic.

## expiration
```yaml
expiration: "ignore"
```
Configures the behavior when the "Expiration Date" of a certificate is
exceeded. If set to "ignore", the "Expiration Date" will be ignored, and a response will
be generated. This is the default setting.
To output a warning at log level Warn, set it to "warn". If set to "invalid",
no response will be generated.

## log
```yaml
log:
  level: "info"
  format: "json"
```
The `log` section configures the log behavior.

|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|level|no|`info`|Log level selected in `error`, `warn`, `info`, `debug`.|
|format|no|`json`|Log format selected in either `json` or `pretty`. The `pretty` format is a human-readable (read on terminal) format.|

## responder
```yaml
responder:
  ca: "sub-ca"
  responder_certificate: "dyocsp/testdata/sub-ocsp-rsa.crt"
  responder_key: "dyocsp/testdata/sub-ocsp-rsa-pkcs8.key"
  issuer_certificate: "dyocsp/testdata/sub-ca-rsa.crt"
```
The `responder` section of the configuration file is used to configure the self
 certificate, key, and issuer for the OCSP responder.
Private key `responder_key` can also be set from the `DYOCSP_PRIVATE_KEY` environment  variable.
However, this configuration is mutually exclusive, and an error occurs if the configuration is duplicated.

|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|ca|yes||`ca` can be used as an index key for tables or data structures in a database.|
|responder_certificate|yes||The path to the responder's certificate.|
|responder_key|yes||The path to the responder's private key. |
|issuer_certificate|yes||The path to the certificate issuer's certificate. |

## cache
```yaml
cache:
  interval: 60
  delay: 5
```
`cache` section configures the life cycle of pre-generated OCSP response caches.
Please refer to the [cache lifecycle](cache_lifecycle.md) document for detailed information about cache.

|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|interval|no|60 (sec)|`interval` configures the duration between `nextUpdate` and `nextUpdate`. The units are in seconds.|
|delay|no|5 (sec)|`delay` configures the duration of delay processing before reaching `nextUpdate`. The units are in seconds.|

## db
```yaml
db:
  dynamodb:
    region: "us-west-2"
    table_name: "test_ca_db"
    ca_gsi: "ca_gsi"
    endpoint: ""
    retry_max_attempts: 0
    timeout: 60
  file:
    file: "testdata/filedb"
```
`db` section configures the type of database and the configuration parameters for the selected database.
Type of database is exclusive, and if the type is duplicated, an error occurs.

### dynamodb
Please refer to the [dynamodb](dynamodb.md) documentation for details about this database type.

|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|region|yes||The DynamoDB Region.|
|table_name|yes||The Name of the table that has revocation information and `dyocsp` will access.|
|ca_gsi|yes||The Name of the required global secondary index.|
|endpoint|no||The Endpoint URL of DynamoDB should be set when using the local DynamoDB server.|
|retry_max_attempts|no|0|`retry_max_attempts` specifies the maximum number attempts an API client will call an operation that fails with a retryable error. A value of 0 is ignored.|
|timeout|no|60|`timeout` parameter specifies the timeout for the API client request.|

### file
Prease refer [file db](fileasdb.md) documentation for details about this database type.

|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|file|yes||The path to file DB.|

## http
```yaml
http:
  addr: ""
  port: 80
  read_timeout: 30
  write_timeout: 0
  read_header_timeout: 10
  max_header_bytes: 1048576 1M
  max_request_bytes: 256
  cache_control_max_age: 60
```
`http` section configures the behavior of the HTTP server.
|Parameter|Required|Default|Description|
| ----------- | ----------- | ----------- | ----------- |
|addr|no||The address for the server to listen on.|
|port|no|80|The port number for the server to listen on.|
|read_timeout|no|30|`read_timeout` is the maximum duration for reading the entire request, including the body. A zero or negative value means there will be no timeout.|
|write_timeout|no|0|`write_timeout` is the maximum duration before timing out writes of the response. A zero or negative value means there will be no timeout.|
|read_header_timeout|no|10|`read_header_timeout` is the amount of time allowed to read request headers. If `read_header_timeout` is zero, the value of ReadTimeout is used.|
|max_header_bytes|no|1048576 (1M)|`max_header_bytes` controls the maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body.|
|max_request_bytes|no|256|`max_request_bytes` defines the maximum size of a request in bytes. Since the content of an OCSP request has a fixed form, the default value is as small as 256 bytes.|
|cache_control_max_age|no|60|`cache_control_max_age` defines the maximum age, in seconds, for a cached response as specified in the Cache-Control max-age directive. If the duration until the nextUpdate of a cached response exceeds MaxAge, the handler sets the response's Cache-Control max-age directive to that duration.|

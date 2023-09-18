# Usage of DynamoDB as DB
## Record Format
When using DynamoDB as a database, it is designed to handle multiple partitions in a single table.
Prease refer [overview](overview.md) documentation for details about certificate revocation data in DyOCSP.

## Table Design
#### Attribute Definitions And Key Schema
|AttributeName|AttributeType|KeyType|
| ----------- | ----------- | ----------- |
|ca|S|HASH|
|serial|S|RANGE|

This key is not used in DyOCSP, but it is useful for managing revocation information.

#### Global Secondary Index
|AttributeName|AttributeType|KeyType|
| ----------- | ----------- | ----------- |
|ca|S|HASH|

DyOCSP uses this global secondary index for utilizing the [Scan API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Scan.html).

#### Required Attributes for An Items
|AttributeName|AttributeType|Description|
| ----------- | ----------- | ----------- |
|ca|S|CA Name|
|serial|S|Serial Number|
|rev_type|S|Revocation Type|
|exp_date|S|Expiration Date|
|rev_date|S|Revoked Date|
|crl_reason|S|CRL Reason|

These attributes are required, and since DyOCSP only requires mandatory
 attributes, any other attributes necessary for the management of private CAs may be attached.

# Basic Usage
### 1. Create Table On AWS Console
Since the creation of a table involves a lot of configuration, only the
 necessary parts will be explained. The instructions will be illustrated with an image of
 the AWS console.

Set up keys of table  as follows.
![DynamodbCreateTable](dynamodb-create-table.png)

Set up global secondary index as follows.
![DynamodbCreateSGI](dynamodb-create-sgi.png)

### Create IAM Policy
The following IAM policy will suffice for DyOCSP:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:Scan"
            ],
            "Resource": "arn:aws:dynamodb:your-region:your-aws-id:table/ca_db"
        }
    ]
}
```

### 2. Prepare CA and Certificate
The following certificates are used here as an example.

server.crt
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

example-ca.crt
```pem
-----BEGIN CERTIFICATE-----
MIICzTCCAbWgAwIBAgIRAMlxjbANYP+VoiqGiu9zV+kwDQYJKoZIhvcNAQELBQAw
ADAeFw0yMzA5MTUwMDI0MTdaFw0zMzA5MTIwMDI0MTdaMAAwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDSnCh7XqoRIqa6ab8ehFSYVLveq2L6D7DuxnZD
Ll0MH2XH2inxbQHaEPwmQe+TTgFZEN8dtA4HCpAX7BvLWKTRm2oHqvo8feZrV5Wz
aH8PMmXxsK1nUu8EEyEbD+FePYpBBpZCPWZ8KzMBGxh/OH6uw5AvFef5zmjtYyU1
w79+f450HNB0UlYOqyfHUBxQf3MpMifrSxwUP4d/elfAwozc18dM9hZNQxValtmA
a0xP+osi2SoTVzZuf83aWfoHVgf2Toi+0IR4IL2Rq+kFwu5rRGWml6X52xN0vy8H
zXfY7hF20447yUVzTmXJMUFeA+NpZ02yGfESjc1xu1tiJLOvAgMBAAGjQjBAMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTdPddMpq/n
eLE+kAh588LASiNZJTANBgkqhkiG9w0BAQsFAAOCAQEAQvwypNE42M20YmsaVOVw
PJEVDF70kBGTBpEZQ+ep2Z0OydF6naa1V/xrpgE0GQcwRdvvBe16psFJJYZxAg1a
kgILZZxdSah69R6xZwCDD3WYHrwl3OK1f/pLMB1o/n64Lh1JoWBN8Ix+cC1cat3r
2Hi/ZjD6WB5hS5RjSdiVui4EqCNLEswG4fqoOkp7xW7nYJh2SnaXwsacQbQHbUZi
WxhJ7DWwPpgUDBYAeyY8+QidRkETy5niniYHV5WXB/PKfHbXURDTdV90zKozsryv
RKARpBvVUYHWpbHEMQfb6FUl3RkxOMsXyjuF/NMMHpT03cajpBQ0z71SDpD6mqkh
3A==
-----END CERTIFICATE-----
```

ocsp.crt
```pem
-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIRAMlxjbANYP+VoiqGiu9zV+0wDQYJKoZIhvcNAQELBQAw
ADAgFw0yMzA5MTUwNDQ1MjVaGA8yMTA1MTEwNDA0NDUyNVowEjEQMA4GA1UECAwH
RXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALHtqud+WpFZ
+V5Pc6p29KeA8ZB5ybMrtJptxWJvCCr5eiRZvuDn32KsrfJi2z19jeY0S1Vghese
OPv74hkOPrAfB/wyjrVXoCPFaLU2grpJ6+UJMr5nKAzduyh4jXqRR3/EJKZ7E0aS
KFkbDP/XrzrOC+dkYih+yJSdntwwxnSctWJLxhSdBCg2ydyeFMJhYLv230XJufE+
GeSHaYzH79FvCoaGyGg+8XMFC/ckOH9VtGIqRDBryz6zFTSCaznIB8X+IZzy/mSb
r9dABbK/TrsGXxoCnb+VQrusGa0fxxrLxuioer+WT9js0FgXdVKi44jrzSpFZ/Q1
irCK6Y/Xi90CAwEAAaN1MHMwHwYDVR0jBBgwFoAU3T3XTKav53ixPpAIefPCwEoj
WSUwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCTAOBgNVHQ8BAf8E
BAMCB4AwHQYDVR0OBBYEFKSuZ/HkVChRwnnc+rcTt5451iYNMA0GCSqGSIb3DQEB
CwUAA4IBAQBQeusCuJBfGWzMgCDnv8g8vlMeFjRp7fle+WNJB++bki9g3DHaiSyN
tOQCHQEC4tV32HOZY0NwoSelAVFZwtp9eSqrO6ztR2iX9l+1N5T3gv/JGJ7w+ZSU
ljzZHzY0Np47lR+G3tGw9oRCX7AzWB1Vl0kXBESz1JnKNJZzejJQ7ZC0gga5vn5Z
MZxj0uyun1P3tXxYBGPcaHWQNl2WfwCQ1CIHsdvJUQhIy77R/sr56N4EsGRWXegA
+keTAHE04/a5SOokl4RzeITDWvI8nG4X/vyC/QcfKOgCSsS3X6ORzQeuJ97QL0Wk
jjRNXAtld2V4bNMyrgvKEm+tdJcqBldy
-----END CERTIFICATE-----
```

ocsp.key
```pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx7arnflqRWfle
T3OqdvSngPGQecmzK7SabcVibwgq+XokWb7g599irK3yYts9fY3mNEtVYIXrHjj7
++IZDj6wHwf8Mo61V6AjxWi1NoK6SevlCTK+ZygM3bsoeI16kUd/xCSmexNGkihZ
Gwz/1686zgvnZGIofsiUnZ7cMMZ0nLViS8YUnQQoNsncnhTCYWC79t9FybnxPhnk
h2mMx+/RbwqGhshoPvFzBQv3JDh/VbRiKkQwa8s+sxU0gms5yAfF/iGc8v5km6/X
QAWyv067Bl8aAp2/lUK7rBmtH8cay8boqHq/lk/Y7NBYF3VSouOI680qRWf0NYqw
iumP14vdAgMBAAECggEAdWKsXx+gVsa6Wzslvy/Nxvit5jhDFr7d3whOsds400lW
CMdgw/aWDP6JoCESLWY5CMg1bzVIBM8inzQVfZxFRWKjnQIp3n/Z+d+SbgNxib+d
LrS70pwx8xMSF+g4xsU0G5nm6CLIm8VvcyICmIPOaohnmBhFHhxO7qVymihftaxW
4ehZijOVLE76ag2gBUF6bbin3/vvBXy98J1AAsRR5fn0jhatKG0p2AMA7izgpTvi
Ot6KjQK3YWnfNniWZwUB5n/Is3yNiYz7uBdZr3vf8wH0UcmaUsLjWwn0KZLSmrhx
DxwDeacRDaWHxRTcFg5SmftE2yQWOWGLmcBljQZYwQKBgQDopixMcwS0MqFW9Q8e
kqWsS6kxvQMmbGOuVuJRhUgpLFBMt5koUPck47w6T16OPuODFvG8oqAczHvvEijg
C6O1ahSHkQbBSk+DuXnqAoqvgvD5pi7Xll1/rpMagws6Nfalh93Cm2HLOOJeM+sj
HyuD97KYJVInIGlswcoO0y/ITQKBgQDDyXeZNbXZaaAvW/ZT197md/5+p7OR/SeP
d5OltxqSoOfB2hyBVmCKbDdUQCcCyR60rFL+RQngsJQLIIuLyVfDOCiIh/URCH8S
g5sx86KFtPFxY/KuJlhO4+2Yfl6hjGwMYSWNuHFAAQ/5Ncu4qvhtIVHwgbb9FYUq
3K1O0xuZ0QKBgHdY59jAGGWoo4PMa1kvubXNipptcDRB3lENWUSgrwgQJ5FzjipU
frR575GqLcOjF2ukVZaDhse/TsSx+C4XSoBCTw3MpD58NJZKi/Q0IZkv/xbS3azT
AlwB3oz3NMdD76ezL1wqAd0S7W2ODM4Tq2sjoobSfnZ79hlIwLMiO5zxAoGAeZjj
5czc73XRnfhQqcwVzS/TaNhBB7eh3VHX6oEpSM4UgmozcAS0muQRDQt27xz4LCAm
v3MjamBg4fRJlvzqu/1h90Hxa63KNjZ0qfZ2BvLVTaZUr+Jy0DRxeVdq8IylAp9H
UpiuBaFjSVUm/L964VRjbqsxekfmWDOMk7s7ljECgYEA0GY/pUCSK4IszHS4Cvzo
yvuwvrpQ6Lt4WsoDJR3LXaL2EIALblUhEl4mT99hdpKi4PUMgyG+AV1Gg4dcaZV7
YL4VMDKwq+SXFyzIFC7V6Nf/8VR0ISST8lfx8JYHf11y+e/AcX67mdNDhJCW+MdA
kUXvZkRRUeJenS7N0dmBpgw=
-----END PRIVATE KEY-----
```

### 2. Put Item
Create an item indicating that the certificate is currently valid, as follows:
![DynamodbCreateItem](dynamodb-create-item.png)
This item is represented in JSON format:
```JSON
{
  "ca": {
    "S": "example-ca"
  },
  "serial": {
    "S": "C9718DB00D60FF95A22A868AEF7357EB"
  },
  "rev_type": {
    "S": "V"
  },
  "exp_date": {
    "S": "330912010907Z"
  },
  "rev_date": {
    "S": ""
  },
  "crl_reason": {
    "S": ""
  }
}
```


### 3. Prepare DyOCSP Configuration
Create a configuration file for DynamoDB:

dyocsp.yml
```
version: 0.1
log:
  level: "info"
  format: "pretty"
responder:
  ca: "example-ca"
  responder_certificate: "ocsp.crt"
  responder_key: "ocsp.key"
  issuer_certificate: "example-ca.crt"
cache:
  interval: 30
  delay: 8
db:
  dynamodb:
    region: "your-region"
    table_name: "ca_db"
    ca_gsi: "ca-index"
    retry_max_attempts: 2
    timeout: 120
http:
  addr: "localhost"
  port: 9080
```

### 4. Run DyOCSP
1. First, set the authentication information.
```
export AWS_ACCESS_KEY_ID=your-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
```
or
```
aws configure set aws_access_key_id dummyaccesskey
aws configure set aws_secret_access_key dummysecretkey
```
2. Second, run `dyocsp`.
```
dyocsp -c dyocsp.yml
```
3. Test OCSP Request.
```
openssl ocsp -CAfile example-ca.crt  -issuer example-ca.crt -cert server.crt -no_nonce -url http://localhost:9080
```

### 5. Update Item to Revoke the Certificate
To update an item indicating that the certificate is currently revoked:
![DynamodbUpdateItem](dynamodb-update-item.png)

This item is represented in JSON format:
```JSON
{
  "ca": {
    "S": "example-ca"
  },
  "serial": {
    "S": "C9718DB00D60FF95A22A868AEF7357EB"
  },
  "crl_reason": {
    "S": "unspecified"
  },
  "exp_date": {
    "S": "330912010907Z"
  },
  "rev_date": {
    "S": "231012010907Z"
  },
  "rev_type": {
    "S": "R"
  }
```

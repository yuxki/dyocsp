# dyocsp manual

## Basic Command Options
#### -c configuraion-file
Specify the format of the YAML configuration file. (Required)
```bash
dyocsp -c config.yml
```

#### -validate
When this option is used, the command will not start the server but will only validate the configuration file.
```bash
dyocsp -validate -c config.yml
```

## Limitations
- [Nonce](https://www.rfc-editor.org/rfc/rfc6960#section-4.4.1) is not supported.
- Multiple certificates in a request are not supported.

## Table of Contents
- [Overview](overview.md)
- [Use File as DB](fileasdb.md)
- [Use DynamoDB as DB](dynamodb.md)
- [Response Cache lifecycle](cache_lifecycle.md)
- [Response patterns](res_patterns.md)
- [Configure a OCSP Responder](config.md)

#!/bin/bash

set -e

aws dynamodb batch-write-item \
  --request-items file://root-ca-item.json \
  --endpoint-url http://dynamodb-local:8000

aws dynamodb batch-write-item \
  --request-items file://sub-ca-item.json \
  --endpoint-url http://dynamodb-local:8000

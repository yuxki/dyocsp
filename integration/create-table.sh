#!/bin/bash

aws dynamodb create-table \
  --table-name "test_ca_db" \
  --attribute-definitions \
  AttributeName=ca,AttributeType=S \
  AttributeName=serial,AttributeType=S \
  --key-schema AttributeName=ca,KeyType=HASH AttributeName=serial,KeyType=RANGE \
  --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
  --global-secondary-indexes "{\"IndexName\":\"ca_gsi\",\"KeySchema\":[{\"AttributeName\":\"ca\",\"KeyType\":\"HASH\"}],\"ProvisionedThroughput\":{\"ReadCapacityUnits\":1,\"WriteCapacityUnits\":1},\"Projection\":{\"ProjectionType\":\"ALL\"}}" \
  --endpoint-url http://dynamodb-local:8000

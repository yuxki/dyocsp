package db

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The DynamoDBClient is an implementation of the CADBClient interface. It is used
// to scan the certificate revocation status from the DynamoDB. Please refer to the
// documentation for specifications on the table and index.
type DynamoDBClient struct {
	client    *dynamodb.Client
	caName    *string
	tableName *string
	indexName *string
	timeout   int
}

// NewDynamoDBClient creates and returns new DynamoDBClient instance.
func NewDynamoDBClient(
	client *dynamodb.Client,
	caName *string,
	tableName *string,
	indexName *string,
	timeout int,
) DynamoDBClient {
	return DynamoDBClient{
		client:    client,
		caName:    caName,
		tableName: tableName,
		indexName: indexName,
		timeout:   timeout,
	}
}

type unmarshalFailedError struct {
	attr string
	msg  string
}

func (e unmarshalFailedError) Error() string {
	return e.msg + ": " + e.attr
}

func unmarshalItem(item map[string]types.AttributeValue, attrName string) (string, error) {
	absCa, ok := item[attrName]
	if !ok {
		return "", unmarshalFailedError{
			attr: attrName,
			msg:  "member not found",
		}
	}
	conCa, ok := absCa.(*types.AttributeValueMemberS)
	if !ok {
		return "", unmarshalFailedError{
			attr: attrName,
			msg:  "unexpected member type found",
		}
	}

	return conCa.Value, nil
}

// Unmarshal the item data retrieved from the DynamoDB read API
// and use it to create an IntermediateEntry.
func UnmarshalDynamoDBItem(item map[string]types.AttributeValue) (IntermidiateEntry, error) {
	ca, err := unmarshalItem(item, "ca")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	serial, err := unmarshalItem(item, "serial")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	revType, err := unmarshalItem(item, "rev_type")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	expDate, err := unmarshalItem(item, "exp_date")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	revDate, err := unmarshalItem(item, "rev_date")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	crlReason, err := unmarshalItem(item, "crl_reason")
	if err != nil {
		return IntermidiateEntry{}, err
	}

	return IntermidiateEntry{
		Ca:        ca,
		Serial:    serial,
		RevType:   revType,
		ExpDate:   expDate,
		RevDate:   revDate,
		CRLReason: crlReason,
	}, nil
}

// Scan read sthe items from the table.
// Set the filter expression to the secondary global index with the "ca" hash key.
// Retrieve the items and unmarshal them into IntermediateEntry.
func (d DynamoDBClient) Scan(ctx context.Context) ([]IntermidiateEntry, error) {
	var input dynamodb.ScanInput

	fex := "ca = :ca"
	pje := "ca,serial,rev_type,exp_date,rev_date,crl_reason"
	eav, err := attributevalue.MarshalMap(map[string]string{":ca": *d.caName})
	if err != nil {
		return nil, err
	}

	input.TableName = d.tableName
	input.IndexName = d.indexName
	input.Select = "SPECIFIC_ATTRIBUTES"
	input.FilterExpression = &fex
	input.ExpressionAttributeValues = eav
	input.ProjectionExpression = &pje

	items := make([]map[string]types.AttributeValue, 0)
	var lastEvaluatedKey map[string]types.AttributeValue

	ctx, cancel := context.WithTimeout(ctx, time.Second*time.Duration(d.timeout))
	defer cancel()
	for {
		input.ExclusiveStartKey = lastEvaluatedKey

		out, err := d.client.Scan(ctx, &input)
		if err != nil {
			return nil, err
		}

		items = append(items, out.Items...)

		if out.LastEvaluatedKey != nil {
			lastEvaluatedKey = out.LastEvaluatedKey
			continue
		}
		break
	}

	entries := make([]IntermidiateEntry, 0, len(items))
	for i := range items {
		e, err := UnmarshalDynamoDBItem(items[i])
		if err != nil {
			continue
		}
		entries = append(entries, e)
	}

	return entries, nil
}

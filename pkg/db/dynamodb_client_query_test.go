package db

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type queryStub struct {
	inputs []*dynamodb.QueryInput
}

func (s *queryStub) Query(
	_ context.Context,
	input *dynamodb.QueryInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.QueryOutput, error) {
	s.inputs = append(s.inputs, input)
	if len(s.inputs) == 1 {
		return &dynamodb.QueryOutput{
			Items:            []map[string]types.AttributeValue{validDynamoDBItem()},
			LastEvaluatedKey: map[string]types.AttributeValue{"serial": &types.AttributeValueMemberS{Value: "1234"}},
		}, nil
	}
	return &dynamodb.QueryOutput{}, nil
}

func validDynamoDBItem() map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"ca":             &types.AttributeValueMemberS{Value: "test-ca"},
		serialAttribute:  &types.AttributeValueMemberS{Value: "1234"},
		revTypeAttribute: &types.AttributeValueMemberS{Value: "V"},
		"exp_date":       &types.AttributeValueMemberS{Value: "300101000000Z"},
		"rev_date":       &types.AttributeValueMemberS{Value: ""},
		"crl_reason":     &types.AttributeValueMemberS{Value: ""},
	}
}

func TestDynamoDBClientScanQueriesConfiguredIndex(t *testing.T) {
	t.Parallel()

	client := &queryStub{}
	caName := "test-ca"
	tableName := "ca-db"
	indexName := "ca-index"
	dbClient := DynamoDBClient{
		client:    client,
		caName:    &caName,
		tableName: &tableName,
		indexName: &indexName,
		timeout:   1,
	}

	entries, err := dbClient.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("Scan() returned %d entries, want 1", len(entries))
	}
	if len(client.inputs) != 2 {
		t.Fatalf("Query() called %d times, want 2", len(client.inputs))
	}

	firstInput := client.inputs[0]
	if firstInput.KeyConditionExpression == nil || *firstInput.KeyConditionExpression != "ca = :ca" {
		t.Fatalf("KeyConditionExpression = %v, want ca partition condition", firstInput.KeyConditionExpression)
	}
	if firstInput.FilterExpression != nil {
		t.Fatalf("FilterExpression = %v, want nil", firstInput.FilterExpression)
	}
	if firstInput.IndexName == nil || *firstInput.IndexName != indexName {
		t.Fatalf("IndexName = %v, want %q", firstInput.IndexName, indexName)
	}
	if !reflect.DeepEqual(client.inputs[1].ExclusiveStartKey, map[string]types.AttributeValue{
		"serial": &types.AttributeValueMemberS{Value: "1234"},
	}) {
		t.Fatalf("second Query() ExclusiveStartKey = %#v", client.inputs[1].ExclusiveStartKey)
	}
}

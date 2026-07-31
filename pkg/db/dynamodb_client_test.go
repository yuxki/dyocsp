package db

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestUnmarshalDynamoDBItemsRejectsPartialResults(t *testing.T) {
	t.Parallel()

	validItem := map[string]types.AttributeValue{
		"ca":             &types.AttributeValueMemberS{Value: "test-ca"},
		"serial":         &types.AttributeValueMemberS{Value: "1234"},
		revTypeAttribute: &types.AttributeValueMemberS{Value: "V"},
		"exp_date":       &types.AttributeValueMemberS{Value: "300101000000Z"},
		"rev_date":       &types.AttributeValueMemberS{Value: ""},
		"crl_reason":     &types.AttributeValueMemberS{Value: ""},
	}
	invalidItem := map[string]types.AttributeValue{
		"ca": &types.AttributeValueMemberS{Value: "test-ca"},
	}

	entries, err := unmarshalDynamoDBItems([]map[string]types.AttributeValue{validItem, invalidItem})
	if err == nil {
		t.Fatal("unmarshalDynamoDBItems() error = nil, want malformed item error")
	}
	if entries != nil {
		t.Fatalf("unmarshalDynamoDBItems() entries = %#v, want nil", entries)
	}
	if !strings.Contains(err.Error(), "DynamoDB item 1") {
		t.Fatalf("unmarshalDynamoDBItems() error = %q, want item index", err)
	}
	if !strings.Contains(err.Error(), "serial") {
		t.Fatalf("unmarshalDynamoDBItems() error = %q, want missing attribute", err)
	}
}

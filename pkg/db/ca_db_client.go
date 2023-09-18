package db

import (
	"context"
)

// IntermediateEntry is a struct that holds raw data scanned from the database
// without any modifications. This structure handles variations in data originating
// from diverse background databases.
type IntermidiateEntry struct {
	Ca        string
	Serial    string
	RevType   string
	ExpDate   string
	RevDate   string
	CRLReason string
}

// CADBClient is an interface that represents a client for scanning a database
// and creating IntermediateEntries.
type CADBClient interface {
	Scan(ctx context.Context) ([]IntermidiateEntry, error)
}

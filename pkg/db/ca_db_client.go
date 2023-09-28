package db

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

package db

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// FileDBClient is an implementation of the CADBClient interface. It scans the
// certificate revocation status from a DB file.
// The DB file format is based on the index file of 'https://github.com/openssl/openssl'.
type FileDBClient struct {
	caName string
	dbFile string
}

// NewFileDBClient creates and returns a new instance of FileDBClient.
func NewFileDBClient(caName string, dbFile string) FileDBClient {
	return FileDBClient{
		caName: caName,
		dbFile: dbFile,
	}
}

// Indexes of tab delimited columns in DB file.
const (
	// Revocation Type.
	FileDBColRevTypeIdx int = 0
	// Expiration Date.
	FileDBColExpDateIdx int = 1
	// Comma delimited Revocation Date and CRL Reason.
	FileDBColRevDateAndCRLReasonIdx int = 2
	// Serial Number.
	FileDBColSerialIdx int = 3
)

// Indexes of comma delimited RevDate and CRLReason.
const (
	// Revocation Date.
	IdxRevDate int = 0
	// CRL Reason.
	IdxCRLReason int = 1
)

// Scan reads a file and parses each line into an IntermediateEntry.
func (h FileDBClient) Scan(ctx context.Context) (entries []IntermidiateEntry, err error) {
	file, err := os.Open(h.dbFile)
	if err != nil {
		return nil, fmt.Errorf("could not read file DB %s: %w", h.dbFile, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}()

	scanner := bufio.NewScanner(file)
	entries = make([]IntermidiateEntry, 0)

	for scanner.Scan() {
		var entry IntermidiateEntry
		entry.Ca = h.caName

		s := scanner.Text()
		cols := strings.Split(s, "\t")

		for idx := range cols {
			switch idx {
			case FileDBColRevTypeIdx:
				entry.RevType = cols[idx]
			case FileDBColExpDateIdx:
				entry.ExpDate = cols[idx]
			case FileDBColRevDateAndCRLReasonIdx:
				if rc := strings.Split(cols[idx], ","); len(rc) == IdxCRLReason+1 {
					entry.RevDate = rc[IdxRevDate]
					entry.CRLReason = rc[IdxCRLReason]
				}
			case FileDBColSerialIdx:
				entry.Serial = cols[idx]
			default:
			}
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

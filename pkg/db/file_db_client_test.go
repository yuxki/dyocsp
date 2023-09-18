package db

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFileDBClient_Scan(t *testing.T) {
	t.Parallel()
	data := []struct {
		testcase string
		// test data
		ca   string
		file string
		// want
		itmdEntries []IntermidiateEntry
		errMsg      string
	}{
		{
			"OpenSSL index file: pattern mixed",
			"test-ca",
			"testdata/openssl_file_db",
			[]IntermidiateEntry{
				{
					"test-ca",
					"8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F5",
					"V",
					"230925234911Z",
					"",
					"",
				},
				{
					"test-ca",
					"2D7BB5572221AFA7D7FB30C8D19D3F693BFEEE14",
					"R",
					"330823234911Z",
					"230826234911Z",
					"unspecified",
				},
				{
					"test-ca",
					"1F8ACD3265E5BA098DEC495EECE41C11BA093463",
					"V",
					"330823234911Z",
					"",
					"",
				},
				{
					"test-ca",
					"8CA7B3FE5D7F007673C18CCC6A1F818085CDC5F7",
					"E",
					"19000914235323Z",
					"",
					"",
				},
				{ // Not tab delimited
					"test-ca",
					"",
					"V  330823234911Z    1F8ACD3265E5BA098DEC495EECE41C11BA093463  unknown  /C=US/O=Example Organization/CN=good",
					"",
					"",
					"",
				},
			},
			"",
		},
		{
			"file is not exist",
			"test-ca",
			"testdata/notfound",
			nil,
			"could not read file DB testdata/notfound: open testdata/notfound: no such file or directory",
		},
	}

	for _, d := range data {
		d := d
		t.Run(d.testcase, func(t *testing.T) {
			t.Parallel()
			client := NewFileDBClient(d.ca, d.file)
			ctx := context.Background()
			result, err := client.Scan(ctx)

			if d.errMsg != "" {
				if d.errMsg != err.Error() {
					t.Fatalf("Expected error message is '%s' bot got: %s", d.errMsg, err)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(d.itmdEntries, result); diff != "" {
				t.Error(diff)
			}
		})
	}
}

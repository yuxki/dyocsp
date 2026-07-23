package dyocsp

import (
	"net/http"
	"testing"
	"time"

	"github.com/yuxki/dyocsp/pkg/config"
)

func TestCreateHTTPServerTimeoutsUseSeconds(t *testing.T) {
	t.Parallel()

	cfg := config.DyOCSPConfig{
		ReadTimeout:       2,
		WriteTimeout:      3,
		ReadHeaderTimeout: 4,
	}
	server := CreateHTTPServer(":8080", cfg, http.NotFoundHandler())

	if server.ReadTimeout != 2*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", server.ReadTimeout, 2*time.Second)
	}
	if server.WriteTimeout != 3*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", server.WriteTimeout, 3*time.Second)
	}
	if server.ReadHeaderTimeout != 4*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want %v", server.ReadHeaderTimeout, 4*time.Second)
	}
}

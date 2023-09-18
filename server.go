package dyocsp

import (
	"net/http"
	"time"

	"github.com/yuxki/dyocsp/pkg/config"
)

func CreateHTTPServer(
	host string,
	cfg config.DyOCSPConfig,
	handler http.Handler,
) *http.Server {
	return &http.Server{
		Addr:              host,
		Handler:           handler,
		ReadTimeout:       time.Duration(cfg.ReadTimeout),
		WriteTimeout:      time.Second * time.Duration(cfg.WriteTimeout),
		ReadHeaderTimeout: time.Second * time.Duration(cfg.ReadHeaderTimeout),
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

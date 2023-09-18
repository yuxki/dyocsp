package main

import (
	"os"

	"github.com/yuxki/dyocsp/pkg/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func setupLogger(cfg config.DyOCSPConfig) {
	// set time field format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// set global log level
	zerolog.SetGlobalLevel(cfg.ZerologLevel)

	// set contexual logger
	w := os.Stderr
	log.Logger = zerolog.New(w).With().Timestamp().Logger().Level(cfg.ZerologLevel)
	if cfg.ZerologFormat == config.PrettyFormat {
		log.Logger = log.Logger.Output(zerolog.ConsoleWriter{Out: w})
	}
}

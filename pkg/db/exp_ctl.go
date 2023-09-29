package db

import (
	"time"
)

// ExpirationControl is responsible for checking if the Expiration Date of a
// CertificateEntry is in the past, as per the application's requirements.
type ExpirationControl struct {
	warnOnExpiration bool
	logger           Logger
}

// ExpirationControlOption is an implementation of the functional options
// pattern.
type ExpirationControlOption = func(*ExpirationControl)

// NewExpirationControl creates and returns a new instance of ExpirationControl.
// It accepts optional functions.
func NewExpirationControl(options ...ExpirationControlOption) *ExpirationControl {
	eCtl := &ExpirationControl{}

	for _, opt := range options {
		opt(eCtl)
	}

	return eCtl
}

// WithWarnOnExpiration sets the value of the Warn On Expiration flag to true.
// When this flag is set to true, the instance will emit warnings instead of
// deleting entries.
func WithWarnOnExpiration() func(*ExpirationControl) {
	return func(c *ExpirationControl) {
		c.warnOnExpiration = true
	}
}

func WithLogger(logger Logger) func(*ExpirationControl) {
	return func(c *ExpirationControl) {
		c.logger = logger
	}
}

// The Do method checks the expiration date of each entry in the received entry slice.
// If the current time is later than the expiration date, the entry is considered invalid.
// Otherwise, the entry is considered valid.
// If the status is 'R', the entry has already expired but is still considered
// valid as an entry.
func (c *ExpirationControl) Do(now time.Time, entries []CertificateEntry) []CertificateEntry {
	valids := make([]CertificateEntry, 0, len(entries))

	for idx := range entries {
		if entries[idx].RevType == Revoked {
			valids = append(valids, entries[idx])
			continue
		}

		if now.Before(entries[idx].ExpDate) {
			valids = append(valids, entries[idx])
			continue
		}

		if c.warnOnExpiration {
			c.logger.WarnMsg(
				entries[idx].Serial, "It is valid but it has exceeded expiration date",
			)
			valids = append(valids, entries[idx])
			continue
		}

		c.logger.InvalidMsg(
			entries[idx].Serial.Text(SerialBase), "It is no longer valid because it has exceeded expiration date",
		)
	}

	return valids
}

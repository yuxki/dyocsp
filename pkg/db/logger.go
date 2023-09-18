package db

import (
	"math/big"
)

// Logger is an interface that logs messages to inform users
// about both invalid `CertificateEntry` instances and entries that are valid but
// require a warning to be displayed.
type Logger interface {
	InvalidMsg(serial string, msg string)
	WarnMsg(serial *big.Int, msg string)
}

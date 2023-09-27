package date

import (
	"time"
)

type Now func() time.Time

// NowGMT equals time.Now().UTC().
// OCSP use GeneralizedTime (https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.1)
// and GeneralizedTime use
// Greenwich Mean Time (Zulu) (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5.2)
func NowGMT() time.Time {
	return time.Now().UTC()
}

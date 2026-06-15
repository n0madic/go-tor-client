package onion

import (
	"time"

	"github.com/n0madic/go-tor-client/pkg/torcrypto"
)

// Time-period and HSDir ring constants (rend-spec-v3).
const (
	periodLengthMinutes = 1440 // default hsdir-interval (24h)
	rotationOffsetMin   = 720  // periods rotate at 12:00 UTC
	hsDirNReplicas      = 2
	hsDirSpreadFetch    = 3
)

// TimePeriod returns the time-period number and length (minutes) for a given
// time, per rend-spec-v3 [TIME-PERIODS]. Callers should pass the consensus
// valid-after time.
func TimePeriod(now time.Time) (num, length uint64) {
	minutes := uint64(now.Unix()) / 60
	num = (minutes - rotationOffsetMin) / periodLengthMinutes
	return num, periodLengthMinutes
}

// SRVForFetch selects which shared-random value a client uses to compute the
// HSDir ring for the current time period. Per [CLIENTFETCH], a client uses the
// current SRV when it is in the segment between a new time period (12:00) and a
// new SRV (00:00), and the previous SRV otherwise. The decision uses the
// consensus valid-after time.
//
// It returns nil only if no usable SRV is available (caller may fall back to a
// disaster SRV).
func SRVForFetch(validAfter time.Time, currentSRV, previousSRV []byte) []byte {
	hour := validAfter.UTC().Hour()
	// [12:00, 24:00): between new TP and new SRV -> current SRV.
	// [00:00, 12:00): between new SRV and new TP -> previous SRV.
	if hour >= 12 {
		if len(currentSRV) == 32 {
			return currentSRV
		}
		return previousSRV
	}
	if len(previousSRV) == 32 {
		return previousSRV
	}
	return currentSRV
}

// DisasterSRV computes the fallback SRV used when the consensus lacks one:
// SHA3-256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num)).
func DisasterSRV(periodNum, periodLength uint64) []byte {
	return torcrypto.SHA3_256([]byte("shared-random-disaster"), int8be(periodLength), int8be(periodNum))
}

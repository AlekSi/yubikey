// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Status represents validation status, as returned by the server.
type Status string

// Known validation statuses.
const (
	StatusOK                  = Status("OK")
	StatusBadOTP              = Status("BAD_OTP")
	StatusReplayedOTP         = Status("REPLAYED_OTP")
	StatusBadSignature        = Status("BAD_SIGNATURE")
	StatusMissingParameter    = Status("MISSING_PARAMETER")
	StatusNoSuchClient        = Status("NO_SUCH_CLIENT")
	StatusOperationNotAllowed = Status("OPERATION_NOT_ALLOWED")
	StatusBackendError        = Status("BACKEND_ERROR")
	StatusNotEnoughAnswers    = Status("NOT_ENOUGH_ANSWERS")
	StatusReplayedRequest     = Status("REPLAYED_REQUEST")
)

func (s Status) Error() string {
	return string(s)
}

// Response represents validation server's response.
type Response struct {
	OTP            string
	Nonce          string
	H              []byte
	T              time.Time
	Status         Status
	Timestamp      int32 // actually, unsigned 24 bit
	SessionCounter int
	SessionUse     int
	Sl             string
}

func lineParseError(line string, err error) error {
	if err == nil {
		return fmt.Errorf("failed to parse response line %q", line)
	}

	return fmt.Errorf("failed to parse response line %q: %s", line, err)
}

func parseAndValidateResponse(r io.Reader, secretKey []byte) (*Response, error) {
	var res Response
	vals := make(url.Values)

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, lineParseError(line, nil)
		}
		k, v := parts[0], parts[1]

		vals.Set(k, v)

		switch k {
		case "otp":
			res.OTP = v

		case "nonce":
			res.Nonce = v

		case "h":
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, lineParseError(line, err)
			}
			res.H = b

		case "t":
			// They return milliseconds after timezone as 4 digits with a leading zero.
			// Yes, I know.
			// https://github.com/Yubico/yubikey-val/blob/784ddf5e20273b274d8ce7df00a9ca82f0eedc78/ykval-common.php#L293-L297
			parts = strings.SplitN(v, "Z", 2)
			if len(parts) != 2 {
				return nil, lineParseError(line, nil)
			}
			ts, err := time.Parse(time.RFC3339, parts[0]+"Z")
			if err != nil {
				return nil, lineParseError(line, err)
			}
			ms, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, lineParseError(line, err)
			}
			res.T = ts.Add(time.Duration(ms) * time.Millisecond)

		case "status":
			res.Status = Status(v)

		case "timestamp":
			i, err := strconv.Atoi(v) //nolint:gosec
			if err != nil {
				return nil, lineParseError(line, err)
			}
			res.Timestamp = int32(i)

		case "sessioncounter":
			i, err := strconv.Atoi(v)
			if err != nil {
				return nil, lineParseError(line, err)
			}
			res.SessionCounter = i

		case "sessionuse":
			i, err := strconv.Atoi(v)
			if err != nil {
				return nil, lineParseError(line, err)
			}
			res.SessionUse = i

		case "sl":
			res.Sl = v

		default:
			return nil, lineParseError(line, nil)
		}
	}

	if s.Err() != nil {
		return nil, s.Err()
	}

	if secretKey != nil {
		if res.H == nil {
			return &res, fmt.Errorf("failed to validate response: missing signature 'h'")
		}

		vals.Del("h")
		h := sign(vals, secretKey)
		if subtle.ConstantTimeCompare(h, res.H) == 0 {
			return &res, fmt.Errorf("failed to validate response: invalid signature")
		}
	}

	if res.Status != StatusOK {
		return &res, res.Status
	}

	return &res, nil
}

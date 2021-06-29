// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AlekSi/yubikey/internal/lt"
)

const (
	// Can be used with YubiCloud (just like any other existing ID).
	testClientID = "1"

	// From spec; not real for YubiCloud.
	testFakeSecretKey = "mG5be6ZJU1qBGz24yPh/ESM3UdU=" //nolint:gosec
)

func newClient(tb testing.TB, clientID, secretKey string) *Client {
	tb.Helper()

	c, err := NewClient(clientID, secretKey)
	require.NoError(tb, err)

	c.HTTPClient = &http.Client{
		Transport: &lt.Transport{Logf: tb.Logf},
	}

	return c
}

func newRealClient(tb testing.TB) *Client {
	tb.Helper()

	clientID, secretKey := os.Getenv("TEST_YUBIKEY_CLIENT_ID"), os.Getenv("TEST_YUBIKEY_SECRET_KEY")
	if clientID == "" || secretKey == "" {
		tb.Skip("TEST_YUBIKEY_CLIENT_ID or TEST_YUBIKEY_SECRET_KEY is not set, skipping.")
	}

	return newClient(tb, clientID, secretKey)
}

func decodeBase64(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(tb, err)
	return b
}

func TestSign(t *testing.T) {
	t.Parallel()

	// https://developers.yubico.com/OTP/Specifications/Test_vectors.html

	vals := make(url.Values)
	vals.Set("id", testClientID)
	vals.Set("otp", "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
	vals.Set("nonce", "jrFwbaYFhn0HoxZIsd9LQ6w2ceU")

	h := sign(vals, decodeBase64(t, testFakeSecretKey))

	specH := "%2Bja8S3IjbX593/LAgTBixwPNGX4%3D"
	rawSpecH, err := url.QueryUnescape(specH)
	require.NoError(t, err)
	assert.Equal(t, decodeBase64(t, rawSpecH), h)

	vals.Set("h", base64.StdEncoding.EncodeToString(h))

	expected := "id=1&nonce=jrFwbaYFhn0HoxZIsd9LQ6w2ceU&otp=vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft"
	specH = strings.ReplaceAll(specH, "/", "%2F") // Go encodes / too
	expected = "h=" + specH + "&" + expected
	assert.Equal(t, expected, vals.Encode())
}

func TestParseAndValidateResponse(t *testing.T) {
	t.Parallel()

	for _, td := range []struct {
		name      string
		body      string
		secretKey []byte
		resp      *Response
		err       error
	}{
		// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
		{
			name: "spec1",
			body: `
h=4uvN1cIqh0vk6bnkO8ya48L2F5c=
t=2020-01-06T02:52:13Z0998
otp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil
nonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e
sl=20
status=OK`,
			resp: &Response{
				OTP:    "cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil",
				Nonce:  "ba336f7fdb9b8fec5d6d70313125d9985f6d295e",
				H:      decodeBase64(t, "4uvN1cIqh0vk6bnkO8ya48L2F5c="),
				T:      time.Date(2020, 1, 6, 2, 52, 13, int(998*time.Millisecond), time.UTC),
				Status: StatusOK,
				Sl:     "20",
			},
		},

		// https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
		{
			name: "spec2",
			body: `
h=paOSl7f61trM4PPLnlFFLuR+z20=
t=2020-01-06T02:52:23Z0098
otp=cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil
nonce=ba336f7fdb9b8fec5d6d70313125d9985f6d295e
status=REPLAYED_REQUEST`,
			resp: &Response{
				OTP:    "cccccckdvvulgjvtkjdhtlrbjjctggdihuevikehtlil",
				Nonce:  "ba336f7fdb9b8fec5d6d70313125d9985f6d295e",
				H:      decodeBase64(t, "paOSl7f61trM4PPLnlFFLuR+z20="),
				T:      time.Date(2020, 1, 6, 2, 52, 23, int(98*time.Millisecond), time.UTC),
				Status: StatusReplayedRequest,
			},
			err: StatusReplayedRequest,
		},
		{
			name: "Test_vectors", // https://developers.yubico.com/OTP/Specifications/Test_vectors.html
			body: `
status=OK
t=2019-06-06T05:14:15Z0369
nonce=0123456789abcdef
otp=cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj
sl=25
h=iCV9uFJDtuyELQsxFPnR80Yj2XU=`,
			secretKey: decodeBase64(t, testFakeSecretKey),
			resp: &Response{
				OTP:    "cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj",
				Nonce:  "0123456789abcdef",
				H:      decodeBase64(t, "iCV9uFJDtuyELQsxFPnR80Yj2XU="),
				T:      time.Date(2019, 6, 6, 5, 14, 15, int(369*time.Millisecond), time.UTC),
				Status: StatusOK,
				Sl:     "25",
			},
		},
	} {
		td := td
		t.Run(td.name, func(t *testing.T) {
			t.Parallel()

			r := strings.NewReader(strings.TrimSpace(td.body) + "\n")
			resp, err := parseAndValidateResponse(r, td.secretKey)
			assert.Equal(t, td.err, err)
			assert.Equal(t, td.resp, resp)
		})
	}
}

func TestClient(t *testing.T) {
	t.Parallel()

	t.Run("SetURLs", func(t *testing.T) {
		t.Parallel()

		c := new(Client)
		for u, expected := range map[string]error{
			"mailto:test@test.test": fmt.Errorf(`URL must start with https://`),
			"https:opaque":          fmt.Errorf(`URL must start with https://`),
			"http://test.test":      fmt.Errorf(`URL must start with https://`),
			"https://test.test":     nil,
			"":                      nil,
		} {
			err := c.SetURL(u)
			assert.Equal(t, err, expected)
		}
	})
}

func TestClientYubiCloud(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping in -short mode.")
	}

	ctx := context.Background()

	t.Run("TestClient", func(t *testing.T) {
		t.Parallel()

		c := newClient(t, testClientID, "")

		c.HTTPClient = &http.Client{
			Transport: &lt.Transport{Logf: t.Logf},
		}

		res, err := c.Validate(ctx, "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
		require.Equal(t, StatusReplayedOTP, err)
		assert.Equal(t, StatusReplayedOTP, res.Status)
		assert.Equal(t, "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft", res.OTP)
	})

	t.Run("RealClient", func(t *testing.T) {
		t.Parallel()

		c := newRealClient(t)

		res, err := c.Validate(ctx, "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
		require.Equal(t, StatusReplayedOTP, err)
		assert.Equal(t, StatusReplayedOTP, res.Status)
		assert.Equal(t, "vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft", res.OTP)
	})
}

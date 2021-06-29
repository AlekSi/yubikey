// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	t.Parallel()

	otp := "vvfbhrhghngettteklnejthbvcehettgdcntrgddknvr"
	secretKey := os.Getenv("TEST_YUBIKEY_DECODE_SECRET_KEY")
	if secretKey == "" {
		t.Skip("TEST_YUBIKEY_DECODE_SECRET_KEY is not set, skipping.")
	}

	actual, err := Decode(otp, secretKey)
	require.NoError(t, err)

	publicIDDec, ok := new(big.Int).SetString("280656456543059", 10)
	require.True(t, ok)

	expected := &Info{
		PublicID:    "vvfbhrhghnge",
		PublicIDBin: []byte{0xff, 0x41, 0x6c, 0x65, 0x6b, 0x53},
		PublicIDHex: "ff416c656b53",
		PublicIDDec: publicIDDec,
	}
	assert.Equal(t, expected, actual)
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testdata struct {
	OTP       string
	SecretKey string

	PublicIDModHex string
	PrivateIDHex   string
}

func TestDecode(t *testing.T) {
	t.Parallel()

	pattern := filepath.Join("testdata", "*.json")
	files, err := filepath.Glob(pattern)
	require.NoError(t, err)

	if len(files) == 0 {
		t.Skipf("no files matching %s, skipping", pattern)
	}

	for _, file := range files {
		file := file
		t.Run(file, func(t *testing.T) {
			t.Parallel()

			b, err := os.ReadFile(file)
			require.NoError(t, err)

			var expected testdata
			err = json.Unmarshal(b, &expected)
			require.NoError(t, err)

			actual, err := Decode(expected.OTP, expected.SecretKey)
			require.NoError(t, err)
			assert.Equal(t, expected.PublicIDModHex, actual.PublicIDModHex())
			assert.Equal(t, expected.PrivateIDHex, actual.PrivateIDHex())
		})
	}
}

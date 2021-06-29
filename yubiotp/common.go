// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

//nolint:gosec
import (
	"crypto/hmac"
	"crypto/sha1"
	"net/url"
	"sort"
)

//nolint:gosec // gosec does not know that mac.Write can't return error
func sign(vals url.Values, secretKey []byte) []byte {
	mac := hmac.New(sha1.New, secretKey)

	// We almost can write `mac.Write([]byte(vals.Encode()))`,
	// but it percent-encodes values like '+' and '/',
	// and we should sign unescaped strings.

	keys := make([]string, 0, len(vals))
	for key := range vals {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for i, key := range keys {
		mac.Write([]byte(key))
		mac.Write([]byte("="))
		mac.Write([]byte(vals.Get(key)))
		if i != len(keys)-1 {
			mac.Write([]byte("&"))
		}
	}

	return mac.Sum(nil)
}

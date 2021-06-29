// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package lt provides logging HTTP transport for testing.
package lt

import (
	"net/http"
	"net/http/httputil"
)

// Transport is logging HTTP transport for testing.
type Transport struct {
	Logf func(format string, args ...interface{})
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, err
	}
	t.Logf("Request:\n%s", b)

	resp, respErr := http.DefaultTransport.RoundTrip(req)

	if resp != nil && resp.Body != nil {
		b, err = httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, err
		}
		t.Logf("Response:\n%s", b)
	}

	return resp, respErr
}

// Check interfaces.
var (
	_ http.RoundTripper = (*Transport)(nil)
)

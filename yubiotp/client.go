// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var defaultURL = url.URL{Scheme: "https", Host: "api.yubico.com", Path: "/wsapi/2.0/verify"}

// Client represents validation server's client.
//
// It can be used with both YubiCloud and self-hosted servers.
//
// See:
//   * https://upgrade.yubico.com/getapikey/
//   * https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html
//   * https://developers.yubico.com/OTP/Specifications/OTP_validation_protocol.html
type Client struct {
	HTTPClient *http.Client

	clientID  string
	secretKey []byte
	u         url.URL
	tolerance time.Duration
}

// NewClient creates a new client with given client ID (required by YubiCloud, use "1" if unknown)
// and base64-encoded secret key (optional).
func NewClient(clientID, secretKey string) (*Client, error) {
	c := &Client{
		clientID:  clientID,
		tolerance: 10 * time.Second,
	}
	err := c.setSecretKey(secretKey)
	return c, err
}

func (c *Client) setSecretKey(secretKey string) error {
	if secretKey == "" {
		c.secretKey = nil
		return nil
	}

	b, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return err
	}
	c.secretKey = b
	return err
}

// SetURL sets self-hosted validation server URL,
// or resets it to use YubiCloud if empty.
func (c *Client) SetURL(rawurl string) error {
	if rawurl == "" {
		c.u = url.URL{}
		return nil
	}

	u, err := url.Parse(rawurl)
	if err != nil {
		return err
	}
	if u.Opaque != "" || u.Scheme != "https" {
		return fmt.Errorf("URL must start with https://")
	}

	c.u = *u
	return nil
}

// Validate calls validation server to check OTP.
//
// In case of validation or any other error, error is returned.
// Non-nil response may be returned if it was parsed, even if validation failed.
func (c *Client) Validate(ctx context.Context, otp string) (*Response, error) {
	if len(otp) < 32 {
		return nil, fmt.Errorf("otp is too short")
	}
	if len(otp) > 48 {
		return nil, fmt.Errorf("otp is too long")
	}

	nonceB := make([]byte, 20)
	if _, err := rand.Read(nonceB); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceB)

	timeout := 10
	if deadline, ok := ctx.Deadline(); ok {
		if t := int(time.Until(deadline).Seconds()); t < timeout {
			timeout = t
		}
	}

	u := defaultURL
	if c.u.Scheme != "" {
		u = c.u
	}

	vals := make(url.Values)
	vals.Set("otp", otp)
	vals.Set("timestamp", "1")
	vals.Set("nonce", nonce)
	vals.Set("timeout", strconv.Itoa(timeout))

	if c.clientID != "" {
		vals.Set("id", c.clientID)
	}

	if c.secretKey != nil {
		h := sign(vals, c.secretKey)
		vals.Set("h", base64.StdEncoding.EncodeToString(h))
	}

	u.RawQuery = vals.Encode()

	// There is no need to call several hosts in parallel anymore:
	// https://status.yubico.com/2021/04/15/one-api-yubico-com-one-http-get/

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "https://github.com/AlekSi/yubikey")

	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response code %d", resp.StatusCode)
	}

	res, err := parseAndValidateResponse(resp.Body, c.secretKey)
	if err != nil {
		return res, err
	}

	if res.OTP != otp {
		return res, fmt.Errorf("unexpected OTP")
	}
	if res.Nonce != nonce {
		return res, fmt.Errorf("unexpected nonce")
	}

	now := time.Now()
	if now.After(res.T.Add(c.tolerance)) {
		return res, fmt.Errorf("response is too old")
	}
	if now.Before(res.T.Add(-c.tolerance)) {
		return res, fmt.Errorf("response is from the future")
	}

	return res, nil
}

// http returns HTTP client to use.
func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}

	return http.DefaultClient
}

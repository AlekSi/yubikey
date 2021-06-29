// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/AlekSi/yubikey/internal/lt"
	"github.com/AlekSi/yubikey/yubiotp"
)

func main() {
	log.SetFlags(log.Lmsgprefix | log.Lshortfile)
	log.SetPrefix("yubiotp: ")
	flag.Parse()

	clientID, secretKey := os.Getenv("YUBIKEY_CLIENT_ID"), os.Getenv("YUBIKEY_SECRET_KEY")

	if clientID == "" {
		log.Printf("YUBIKEY_CLIENT_ID is not set, assuming '1'.")
		clientID = "1"
	} else {
		log.Printf("YUBIKEY_CLIENT_ID is set, using it.")
	}

	if secretKey == "" {
		log.Printf("YUBIKEY_SECRET_KEY is not set, skipping signing.")
	} else {
		log.Printf("YUBIKEY_SECRET_KEY is set, enabling signing.")
	}

	fmt.Println("Please touch the YubiKey button.")
	var otp string
	_, err := fmt.Scanln(&otp)
	if err != nil {
		log.Fatal(err)
	}

	c, err := yubiotp.NewClient(clientID, secretKey)
	if err != nil {
		log.Fatal(err)
	}

	c.HTTPClient = &http.Client{
		Transport: &lt.Transport{
			Logf: log.Printf,
		},
	}
	res, err := c.Validate(context.TODO(), otp)
	fmt.Printf("%+v\n", res)
	if err != nil {
		log.Fatal(err)
	}
}

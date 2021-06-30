// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/AlekSi/modhex"
)

type Info struct {
	PublicIDBin  []byte
	PrivateIDBin []byte

	Rnd uint16
}

func (i *Info) PublicIDModHex() string {
	return modhex.EncodeToString(i.PublicIDBin)
}

func (i *Info) PublicIDHex() string {
	return hex.EncodeToString(i.PublicIDBin)
}

func (i *Info) PublicIDDec() *big.Int {
	return new(big.Int).SetBytes(i.PublicIDBin)
}

func (i *Info) PrivateIDModHex() string {
	return modhex.EncodeToString(i.PrivateIDBin)
}

func (i *Info) PrivateIDHex() string {
	return hex.EncodeToString(i.PrivateIDBin)
}

func (i *Info) PrivateIDDec() *big.Int {
	return new(big.Int).SetBytes(i.PrivateIDBin)
}

func Decode(otp string, secretKey string) (*Info, error) {
	if len(otp) != 44 {
		return nil, fmt.Errorf("not a 44-character long OTP")
	}

	otpB, err := modhex.DecodeString(otp)
	if err != nil {
		return nil, err
	}

	info := &Info{
		PublicIDBin: otpB[:6],
	}

	if secretKey == "" {
		return info, nil
	}

	secretKeyB, err := hex.DecodeString(secretKey)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(secretKeyB)
	if err != nil {
		return nil, err
	}

	d := make([]byte, c.BlockSize())
	c.Decrypt(d, otpB[6:])

	log.Print(hex.Dump(d))

	info.PrivateIDBin = d[:6]

	return info, nil
}

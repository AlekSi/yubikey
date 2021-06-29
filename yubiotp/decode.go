// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package yubiotp

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/AlekSi/modhex"
)

type Info struct {
	PublicID    string
	PublicIDBin []byte
	PublicIDHex string
	PublicIDDec *big.Int
}

func Decode(otp string, secretKey string) (*Info, error) {
	if len(otp) != 44 {
		return nil, fmt.Errorf("not a 44-character long OTP")
	}

	b, err := modhex.DecodeString(otp)
	if err != nil {
		return nil, err
	}

	info := &Info{
		PublicID:    otp[:12],
		PublicIDBin: b[:6],
		PublicIDHex: hex.EncodeToString(b[:6]),
		PublicIDDec: new(big.Int).SetBytes(b[:6]),
	}

	return info, nil
}

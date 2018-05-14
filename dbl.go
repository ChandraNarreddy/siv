package siv

import "crypto/subtle"

func dbl(src []byte) []byte {
	var bit byte // initialized to zero
	ret := make([]byte, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		b := src[i] >> 7
		ret[i] = src[i]<<1 | bit
		bit = b
	}
	ret[len(ret)-1] ^= byte(subtle.ConstantTimeSelect(int(bit), 0x87, 0))
	return ret
}

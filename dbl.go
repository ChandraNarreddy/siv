package siv

import "crypto/subtle"

func dbl(src []byte) []byte {
	var carryoverbit byte // initialized to zero
	dst := make([]byte, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		dst[i] = src[i]<<1 | carryoverbit
		carryoverbit = src[i] >> 7
	}
	dst[len(dst)-1] ^= byte(subtle.ConstantTimeSelect(int(carryoverbit), 0x87, 0))
	return dst
}

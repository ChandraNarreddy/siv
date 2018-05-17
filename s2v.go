package siv

import (
	"errors"
)

var (
	zero = []byte{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	one = []byte{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01}
)

var (
	//ErrAesSIVs2v indicates that the AesSIVs2v routine failed
	ErrAesSIVs2v = errors.New("AES SIV s2v error: s2v routine failed")
)

func s2v(sivpair sivBlockPair, plaintext []byte, additionalData ...[]byte) ([]byte, error) {
	if len(plaintext) == 0 && len(additionalData) == 0 {
		return sivpair.Cmac(one)
	}
	d, cmacErr := sivpair.Cmac(zero)
	if cmacErr != nil {
		return nil, ErrAesSIVs2v
	}

	for _, ad := range additionalData {
		mac, macErr := sivpair.Cmac(ad)
		if macErr != nil {
			return nil, ErrAesSIVs2v
		}
		xor(d, dbl(d), mac)
	}
	var t []byte
	if len(plaintext) >= sivpair.CMACBlockSize() {
		t = make([]byte, len(plaintext))
		xorend(t, plaintext, d)
	} else {
		t = make([]byte, sivpair.CMACBlockSize())
		xor(t, dbl(d), pad(plaintext, sivpair.CMACBlockSize()))
	}
	return sivpair.Cmac(t)
}

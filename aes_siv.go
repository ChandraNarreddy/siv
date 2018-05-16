package siv

import (
	"crypto/subtle"
	"errors"
	"strconv"
	//https://github.com/aead/cmac/blob/master/cmac.go
)

var (
	//ErrAesSIVGeneric indicates a generic error with AesSIV
	ErrAesSIVGeneric = errors.New("AES SIV Generic error: Something went wrong")
	//ErrSivWrapGeneric indicates that an error occurred during the Wrap() function of AesSIV
	ErrSivWrapGeneric = errors.New("Siv Wrap error: error wrapping the message")
	//ErrSivWrapUnsupportedPlaintext indicates that the plaintext supplied to the AesSIV wrap() function is longer than supported (size is platform specific)
	ErrSivWrapUnsupportedPlaintext = errors.New("Siv Wrap error: plaintext size is longer than supported")
	//ErrSivWrapUnsupportedAdditionalData indicates that the additionalData elements supplied exceed the maximum number supported
	ErrSivWrapUnsupportedAdditionalData = errors.New("Siv Wrap error: additionalData elements more than than supported")
	//ErrSivUnwrapGeneric indicates that an error occurred during unwrap() function of AesSIV
	ErrSivUnwrapGeneric = errors.New("Siv Unwrap error: error unwrapping the ciphertext")
	//ErrFailSivUnwrap indicates that the AesSIV unwrap() function failed for the combination of key, ciphertext and additionalData
	ErrFailSivUnwrap = errors.New("Siv Unwrap: Unwrapping the ciphertext failed")
	//ErrSivUnWrapSizeUnsupportedCiphertext indicates that the ciphertext supplied to the AesSIV unwrap() function is longer than supported (size is platform specific)
	ErrSivUnWrapSizeUnsupportedCiphertext = errors.New("Siv Unwrap error: ciphertext size is longer than supported")
	//ErrSivUnWrapUnsupportedAdditionalData indicates that the additionalData elements supplied exceed the maximum number supported
	ErrSivUnWrapUnsupportedAdditionalData = errors.New("Siv Unwrap error: additionalData elements more than than supported")
)

const (
	clearer = 0x7F
)

type aesSiv struct {
	sivBlockPair
}

func (c *aesSiv) CMACBlockSize() int {
	return c.sivBlockPair.CMACBlockSize()
}

func (c *aesSiv) CTRBlockSize() int {
	return c.sivBlockPair.CTRBlockSize()
}

func (c *aesSiv) Wrap(plaintext []byte, additionalData ...[]byte) ([]byte, error) {
	ctrBlockSize := c.CTRBlockSize()
	cmacBlockSize := c.CMACBlockSize()
	if len(plaintext) > (1 << (strconv.IntSize - 3)) {
		return nil, ErrSivWrapUnsupportedPlaintext
	}
	if len(additionalData) > (cmacBlockSize*8)-2 {
		return nil, ErrSivWrapUnsupportedAdditionalData
	}
	v, s2verror := s2v(c.sivBlockPair, plaintext, additionalData...)
	if s2verror != nil {
		return nil, s2verror
	}
	ciphertext := make([]byte, len(plaintext)+ctrBlockSize)
	copy(ciphertext, v)
	v[8] = v[8] & clearer
	v[12] = v[12] & clearer
	c.sivBlockPair.Ctr(ciphertext[ctrBlockSize:], v, plaintext)
	return ciphertext, nil
}

func (c *aesSiv) Unwrap(ciphertext []byte, additionalData ...[]byte) ([]byte, error) {
	ctrBlockSize := c.CTRBlockSize()
	cmacBlockSize := c.CMACBlockSize()
	if len(ciphertext)-ctrBlockSize > (1 << (strconv.IntSize - 3)) {
		return nil, ErrSivUnWrapSizeUnsupportedCiphertext
	}
	if len(additionalData) > (cmacBlockSize*8)-2 {
		return nil, ErrSivUnWrapUnsupportedAdditionalData
	}
	v := make([]byte, ctrBlockSize)
	copy(v, ciphertext)
	q := make([]byte, len(v))
	copy(q, v)
	q[8] = q[8] & clearer
	q[12] = q[12] & clearer
	plaintext := make([]byte, len(ciphertext)-ctrBlockSize)
	c.sivBlockPair.Ctr(plaintext, q, ciphertext[ctrBlockSize:])
	t, s2verror := s2v(c.sivBlockPair, plaintext, additionalData...)
	if s2verror != nil {
		return nil, s2verror
	}
	if subtle.ConstantTimeCompare(t, v) != 1 {
		return nil, ErrFailSivUnwrap
	}
	return plaintext, nil
}

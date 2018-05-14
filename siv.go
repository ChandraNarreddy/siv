package siv

import (
	"errors"
)

// ErrSiv indicates that NewSIV() failed to return an SIV implementation
var ErrSiv = errors.New("NewSIV() error: error returning a new SIV implementation")

//SIV is the SIV operation mode for SIV proposed by Phil Rogaway and Thomas Shrimpton
//standardized as https://tools.ietf.org/html/rfc5297
type SIV interface {
	//Wrap encrypts and authenticates the plaintext using SIV mode
	// Wrap (destination, plaintext, ...additionalData) (cipherText, error)
	Wrap(plaintext []byte, additionalData ...[]byte) ([]byte, error)
	//Unwrap
	//Unwrap(destination, ciphertext, ...associatedData) (plaintext, error)
	Unwrap(ciphertext []byte, additionalData ...[]byte) ([]byte, error)
	//KeySize() returns the key size of the SIV mode
	CMACBlockSize() int
	CTRBlockSize() int
}

// SivAble is an interface implemented by ciphers that have a specific optimized
// implementation of SIV
type sivAble interface {
	newSIV() (SIV, error)
}

// NewSIV returns the given block cipher wrapped in SIV mode
func NewSIV(sivpair sivBlockPair) (SIV, error) {
	if c, ok := sivpair.(sivAble); ok {
		return c.newSIV()
	}
	return nil, ErrSiv
}

type sivBlockPair interface {
	CMACBlockSize() int
	CTRBlockSize() int
	Cmac(src []byte) ([]byte, error)
	Ctr(dst, iv, src []byte) []byte
}

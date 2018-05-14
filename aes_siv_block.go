package siv

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/aead/cmac"
)

var (
	//ErrAesSIVinitKeySize indicates that the key supplied to create an AesSIVBlockPair is in unsupported
	ErrAesSIVinitKeySize = errors.New("Aes SIV Init error: Key size is unsupported")
	//ErrAesSIVinitGeneric indicates that an error occurred initiating an AesSIVBlockPair
	ErrAesSIVinitGeneric = errors.New("AES SIV Init error: Initializing AES SIV block failed")
)

type aesSIVBlockPair struct {
	Cmacblock cipher.Block
	Ctrblock  cipher.Block
}

//NewAesSIVBlockPair function takes a 256, 384 or 512 bit key and returns an AesSIVBlockPair.
func NewAesSIVBlockPair(key []byte) (*aesSIVBlockPair, error) {
	switch len(key) {
	default:
		return nil, ErrAesSIVinitKeySize
	case 32, 48, 64:
		break
	}
	cmac, ciphererr := aes.NewCipher(key[:((len(key)) / 2)])
	if ciphererr != nil {
		return nil, ErrAesSIVinitGeneric
	}
	ctr, ciphererr := aes.NewCipher(key[((len(key)) / 2):])
	if ciphererr != nil {
		return nil, ErrAesSIVinitGeneric
	}
	return &aesSIVBlockPair{
		Cmacblock: cmac,
		Ctrblock:  ctr,
	}, nil
}

func (aespair *aesSIVBlockPair) CMACBlockSize() int {
	return aespair.Cmacblock.BlockSize()
}

func (aespair *aesSIVBlockPair) CTRBlockSize() int {
	return aespair.Ctrblock.BlockSize()
}

func (aespair *aesSIVBlockPair) Cmac(src []byte) ([]byte, error) {
	return cmac.Sum(src, aespair.Cmacblock, aespair.CMACBlockSize())
}

func (aespair *aesSIVBlockPair) Ctr(dst, iv, src []byte) []byte {
	stream := cipher.NewCTR(aespair.Ctrblock, iv)
	stream.XORKeyStream(dst, src)
	return dst
}

var _ sivAble = (*aesSIVBlockPair)(nil)

func (aespair *aesSIVBlockPair) newSIV() (SIV, error) {
	siv := &aesSiv{
		sivBlockPair: aespair,
	}
	return siv, nil
}

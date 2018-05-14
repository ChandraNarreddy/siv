package siv

import (
	"log"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

var (
	rfc5297A1key = []byte{0xff, 0xfe, 0xfd, 0xfc,
		0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4,
		0xf3, 0xf2, 0xf1, 0xf0,
		0xf0, 0xf1, 0xf2, 0xf3,
		0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb,
		0xfc, 0xfd, 0xfe, 0xff}

	rfc5297A1ad = [][]byte{{0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27}}

	rfc5297A1plaintext = []byte{0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc,
		0xdd, 0xee}

	rfc5297A1encrypted = []byte{0x85, 0x63, 0x2d, 0x07,
		0xc6, 0xe8, 0xf3, 0x7f,
		0x95, 0x0a, 0xcd, 0x32,
		0x0a, 0x2e, 0xcc, 0x93,
		0x40, 0xc0, 0x2b, 0x96,
		0x90, 0xc4, 0xdc, 0x04,
		0xda, 0xef, 0x7f, 0x6a,
		0xfe, 0x5c}
)

func TestAesSIVRfc5297A1(t *testing.T) {

	pair, pairErr := NewAesSIVBlockPair(rfc5297A1key)
	if pairErr != nil {
		log.Fatal(pairErr)
	}
	siv, siverr := NewSIV(pair)
	//siv, siverr := pair.NewSIV()
	if siverr != nil {
		log.Fatal(siverr)
	}
	sivWrap, wrapErr := siv.Wrap(rfc5297A1plaintext, rfc5297A1ad...)
	if wrapErr != nil {
		log.Fatal(wrapErr)
	}
	if !(reflect.DeepEqual(sivWrap, rfc5297A1encrypted)) {
		t.Errorf("SIV Wrap failure")
	}

	sivUnwrap, UnwrapErr := siv.Unwrap(sivWrap, rfc5297A1ad...)
	if UnwrapErr != nil {
		log.Fatal(UnwrapErr)
	}
	if !(reflect.DeepEqual(sivUnwrap, rfc5297A1plaintext)) {
		t.Errorf("SIV Unwrap failure")
	}
}

func TestAesSIVRandom(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	key := make([]byte, 48)
	r.Read(key)

	adLength := r.Intn(126)
	ad := make([][]byte, adLength)
	for i := 0; i < adLength; i++ {
		data := make([]byte, i+40)
		r.Read(data)
		copy(ad[i], data)
	}

	plainBytesLength := r.Intn(1 << 26) //restricting to 64 MB max size payloads for testing
	plainBytes := make([]byte, plainBytesLength)
	r.Read(plainBytes)

	pair, pairErr := NewAesSIVBlockPair(key)
	if pairErr != nil {
		log.Fatal(pairErr)
	}
	siv, siverr := NewSIV(pair)
	//siv, siverr := pair.NewSIV()
	if siverr != nil {
		log.Fatal(siverr)
	}
	sivWrap, wrapErr := siv.Wrap(plainBytes, ad...)
	if wrapErr != nil {
		log.Fatal(wrapErr)
	}

	sivUnwrap, UnwrapErr := siv.Unwrap(sivWrap, ad...)
	if UnwrapErr != nil {
		log.Fatal(UnwrapErr)
	}
	if !(reflect.DeepEqual(sivUnwrap, plainBytes)) {
		t.Errorf("SIV Unwrap failure")
	}

}

func BenchmarkWithRfc5297A1Wrap(b *testing.B) {
	pair, pairErr := NewAesSIVBlockPair(rfc5297A1key)
	if pairErr != nil {
		log.Fatal(pairErr)
	}
	siv, siverr := NewSIV(pair)
	//siv, siverr := pair.NewSIV()
	if siverr != nil {
		log.Fatal(siverr)
	}
	benchmarkAesSivWrap(b, siv, rfc5297A1plaintext, rfc5297A1ad...)
	benchmarkAesSivUnwrap(b, siv, rfc5297A1encrypted, rfc5297A1ad...)
}

func BenchmarkWithRfc5297A1UnWrap(b *testing.B) {
	pair, pairErr := NewAesSIVBlockPair(rfc5297A1key)
	if pairErr != nil {
		log.Fatal(pairErr)
	}
	siv, siverr := NewSIV(pair)
	//siv, siverr := pair.NewSIV()
	if siverr != nil {
		log.Fatal(siverr)
	}
	benchmarkAesSivUnwrap(b, siv, rfc5297A1encrypted, rfc5297A1ad...)
}

func benchmarkAesSivWrap(b *testing.B, siv SIV, plaintext []byte, additionalData ...[]byte) {
	for i := 0; i < b.N; i++ {
		siv.Wrap(plaintext, additionalData...)
	}
}

func benchmarkAesSivUnwrap(b *testing.B, siv SIV, ciphertext []byte, additionalData ...[]byte) {
	for i := 0; i < b.N; i++ {
		siv.Unwrap(ciphertext, additionalData...)
	}
}

# siv
SIV-AES (rfc5297) implementation for Golang.

[SIV](https://iacr.org/archive/eurocrypt2006/40040377/40040377.pdf) was proposed by Phil Rogaway and Thomas Shrimpton. Synthetic Initialization Vector (SIV) Authenticated Encryption Using the Advanced Encryption Standard (AES) was proposed as a nonce-reuse misuse resistant Deterministic Authenticated Encryption mechanism in [rfc5297](https://tools.ietf.org/html/rfc5297).

## Usage
* Import siv into your source
```
go get https://github.com/ChandraNarreddy/siv
```
```
import "github.com/ChandraNarreddy/siv"
```
* Create a Blockpair as -
```
pair, _ := NewAesSIVBlockPair([]key)
```
* Instantiate SIV as -
```
siv, _ := NewSIV(pair)
```
* Wrap plaintext and additionalData using -
```
plainBytes := []byte(plainText)
additionalDataBytes := [][]byte{[]byte("first additional data"), []byte("second additional data")}
cipherBytes, _ := siv.Wrap(plainBytes, additionalDataBytes...)
```
* To Unwrap an encrypted bytes -
```
plainBytes, failure := siv.Unwrap(cipherBytes, additionalDataBytes...)
if failure != nil {
  //Unwrap failed because of wrong {cipherBytes, additionalDataBytes... and key) combination
} else {
//do what you want to do with plainBytes here
}
```
## Author

**Chandrakanth Narreddy**

## Contributing
Please submit issues for suggestions. Pull requests are welcome too.

## License

MIT License

## Acknowledgments

* Andreas Auernhammer for [CMAC](https://github.com/aead/cmac)

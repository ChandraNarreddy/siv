# siv
SIV-AES (rfc5297) implementation for Go.

## Usage
* Import siv package into your source
```
go get https://github.com/ChandraNarreddy/siv
```
```
import github.com/ChandraNarreddy/siv
```
* Create the Blockpair as -
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
* To Unwrap a cipherBytes - 
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

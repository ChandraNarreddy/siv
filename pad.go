package siv

func pad(src []byte, paddedSize int) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	dst = append(dst, 0x80)
	for i := len(src) + 1; i <= paddedSize; i++ {
		dst = append(dst, 0x00)
	}
	return dst
}

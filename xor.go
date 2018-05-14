package siv

func xor(dst, a, b []byte) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	//dst = make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func xorend(dst, a, b []byte) {
	copy(dst, a)
	for i := 0; i < len(b); i++ {
		dst[i+(len(a)-len(b))] = dst[i+(len(a)-len(b))] ^ b[i]
	}
}

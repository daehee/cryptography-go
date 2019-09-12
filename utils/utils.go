package utils

import (
	"encoding/base64"
	"encoding/hex"
)

func XorHex(a, b string) string {
	aHex, _ := hex.DecodeString(a)
	bHex, _ := hex.DecodeString(b)

	xored := make([]byte, len(aHex))
	for i := range aHex {
		xored[i] = aHex[i] ^ bHex[i]
	}

	return hex.EncodeToString(xored)
}

func HexToBase64(s string) string {
	hx, _ := hex.DecodeString(s)
	return base64.StdEncoding.EncodeToString([]byte(hx))
}

func XorByte(a []byte, k byte) []byte {
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ k
	}
	return res
}

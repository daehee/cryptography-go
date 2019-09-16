package utils

import (
	"encoding/base64"
	"encoding/hex"
)

type Decoded struct {
	Str   string
	Count int
	Key   byte
}

func FindMax(ds []Decoded) Decoded {
	maxCount := ds[0].Count
	maxString := ds[0].Str
	maxKey := ds[0].Key

	for _, d := range ds {
		if d.Count > maxCount {
			maxCount = d.Count
			maxString = d.Str
			maxKey = d.Key
		}
	}
	return Decoded{maxString, maxCount, maxKey}
}

func Attack1XOR(b []byte) []Decoded {
	ds := make([]Decoded, 0)
	// for k := 126; k < 127; k++ {
	for k := 0; k < 256; k++ {
		d := Decoded{}
		d.Str = string(XorByte(b, byte(k)))
		d.Count = Frequency(d.Str)
		d.Key = byte(k)
		ds = append(ds, d)
	}
	return ds
}

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

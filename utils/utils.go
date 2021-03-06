package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	mRand "math/rand"
	"time"
)

type Decoded struct {
	Str   string
	Count int
	Key   byte
}

func fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func RandBool() bool {
	randByte := RandBytes(1)
	return (randByte[0] % 2) == 0
}

func RandBytes(size int) []byte {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Failed to generate %d random bytes: %s", size, err)
	}
	return key
}

func RandInt(min, max int) int {
	mRand.Seed(time.Now().UnixNano())
	return mRand.Intn(max-min+1) + min
}

func RandByteAppend(buffer []byte) []byte {
	front := RandBytes(RandInt(5, 10))
	back := RandBytes(RandInt(5, 10))
	fmt.Printf("[*] Appending Front (%d): %v\n", len(front), front)
	fmt.Printf("[*] Appending Back (%d): %v\n", len(back), back)

	var res []byte
	res = append(res, front...)
	res = append(res, buffer...)
	res = append(res, back...)
	return res
}

func XORBytes(a, b []byte) []byte {
	out := a
	for i, char := range a {
		// Iterate over each XOR key based on input string position
		// Modulo: a modulo n is the remainder from the division of a by n
		keyPos := i % len(b)
		out[i] = char ^ b[keyPos]
	}
	return out
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

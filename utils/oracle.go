package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

type oracleFunc func(buffer, key []byte) []byte

func EncOracle(buffer, key []byte) []byte {
	appended := RandByteAppend(buffer)
	appended = PadPKCS7(appended, []byte("\x00"), len(key))
	var ciphertext []byte
	if RandBool() {
		// if true, encrypt by ECB
		fmt.Println("[*] ECB Encrypting")
		ciphertext = EncryptAES128ECB(appended, key)
		// fmt.Println("[*] Test Decrypt:")
		// fmt.Printf("%v", string(DecryptAES128ECB(ciphertext, key)))
	} else {
		// else encrypt by CBC
		fmt.Println("[*] CBC Encrypting")
		iv := RandBytes(16)
		ciphertext = EncryptAES128CBC(appended, key, iv)
		// fmt.Println("[*] Test Decrypt:")
		// fmt.Printf("%v", string(DecryptAES128CBC(ciphertext, key, iv)))
	}
	return ciphertext
}

func EncOracleUnknownString(buffer, key []byte) []byte {
	unknownBase64 := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	unknownDecoded, _ := base64.StdEncoding.DecodeString(unknownBase64)
	buffer = append(buffer, unknownDecoded...)
	buffer = PadPKCS7(buffer, []byte("\x00"), len(key))
	ciphertext := EncryptAES128ECB(buffer, key)
	return ciphertext
}

// Increase the size of the plaintext byte-by-byte until the ciphertext increases
// The diff between the ciphertext sizes should be of block size
func oracleBlockSize(oracle oracleFunc, key []byte) int {
	blockSize := 0
	lastKnown := 0
	i := 1
	for {
		input := []byte(strings.Repeat("A", i))
		out := oracle(input, key)
		// get first size, then second size when len jumps
		if lastKnown == 0 {
			lastKnown = len(out)
		} else if len(out) != lastKnown {
			blockSize = len(out) - lastKnown
			break
		}
		i++
	}
	return blockSize
}

func oracleUnknownStringSize(oracle oracleFunc, key []byte) int {
	stringSize := 0
	lastKnown := 0
	i := 1
	for {
		input := []byte(strings.Repeat("A", i))
		out := oracle(input, key)
		// get first size, then second size when len jumps
		if lastKnown == 0 {
			lastKnown = len(out)
		} else if len(out) != lastKnown {
			// ? lastKnown vs len(out)
			stringSize = lastKnown - i
			break
		}
		i++
	}
	return stringSize
}

func OracleUnknownString(key []byte) []byte {
	blockSize := oracleBlockSize(EncOracleUnknownString, key)
	testECBString := "YELLOW SUBMARINEYELLOW SUBMARINE"
	isECB := DetectECB(EncOracleUnknownString([]byte(testECBString), key), blockSize)
	if !isECB {
		fmt.Println("[!] Not ECB Mode")
		return nil
	}
	fmt.Println("[!] Detected ECB Mode, continuing...")
	unknownSize := oracleUnknownStringSize(EncOracleUnknownString, key)
	fmt.Printf("[*] Unknown string size: %d\n", unknownSize)
	unknownRounded := (unknownSize/blockSize + 1) * blockSize
	fmt.Printf("[*] Rounded unknown string size: %d\n", unknownRounded)
	unknown := make([]byte, 0)
	for i := unknownRounded - 1; i >= 0; i-- {
		tmpInput := []byte(strings.Repeat("A", i))
		c1 := EncOracleUnknownString(tmpInput, key)[:unknownRounded]
		for j := 0; j < 256; j++ {
			e := append(tmpInput, unknown...)
			e = append(e, byte(j))
			c2 := EncOracleUnknownString(e, key)[:unknownRounded]
			if bytes.Compare(c1, c2) == 0 {
				unknown = append(unknown, byte(rune(j)))
				break
			}
		}
	}
	return unknown
}

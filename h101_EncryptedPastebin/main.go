package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const (
	BASE_URL      = "http://34.74.105.127/c5b8be066b/?post="
	PADDING_ERROR = "PaddingException"
	BLOCKSIZE     = 16
)

var dReplacer = strings.NewReplacer("~", "=", "!", "/", "-", "+")
var eReplacer = strings.NewReplacer("=", "~", "/", "!", "+", "-")

func b64d(s string) string {
	// Replace special characters ~ -> =, ! -> /, - -> +
	replaced := dReplacer.Replace(s)
	// Decode from Base64
	decoded, err := base64.StdEncoding.DecodeString(replaced)
	if err != nil {
		log.Fatal("b64d decoding error")
	}
	return string(decoded)
}

func b64e(s string) string {
	// Encode as Base64
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	// Replace special characters
	replaced := eReplacer.Replace(encoded)
	return replaced
}

func verifyPadding(testURL string) bool {
	resp, err := http.Get(testURL)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if strings.Contains(string(body), PADDING_ERROR) {
		return false
	}

	fmt.Println(string(body))
	return true
}

// To be run on each 16 byte block of the ciphertext
// Run this on index 0 to len(blocks) - 1, since cipher is i + 1
func attack(i int, blocks []string, plain []string) {
	// Set current block as intermediate value
	iv := blocks[i]
	// Set next block as the ciphertext
	cipher := blocks[i+1]
	// split iv as a slice for easy processing
	ivChs := []rune(iv)
	// iv index
	ivIdx := 15
	// store intermediate values
	mVal := make([]rune, 16)
	for i, _ := range mVal {
		mVal[i] = 'a'
	}

	// Continuously loop while iv index >= 0
	for ivIdx >= 0 {
		// Skip this in first iteration where ivIdx is 15
		if ivIdx != 15 {
			for i := ivIdx + 1; i < 16; i++ {
				// Update iv
				ivChs[i] = rune(byte(mVal[i]) ^ byte(16-ivIdx))
			}
		}

		// range through 0...255
		for k := 0; k < 256; k++ {
			// set iv character value to rune of current loop
			ivChs[ivIdx] = rune(k)
			data := string(ivChs) + cipher

			newURL := BASE_URL + b64e(data)
			fmt.Println(newURL)

			if verifyPadding(newURL) {
				mVal[ivIdx] = rune(byte(k) ^ byte(16-ivIdx))
				break
			}
		}

		ivIdx--
	}

	mValueStr := string(mVal)
	plain[i] = myXor(mValueStr, iv)
}

func myXor(s1, s2 string) string {
	var sNew string
	for i, _ := range s1 {
		sNew += string(rune(byte(s1[i]) ^ byte(s2[i])))
	}
	return sNew
}

func main() {
	// Sample token from request "test"
	token := "O6-TCHd7qilcnyFAcsrgeTZP9FWyGXSPx7eI3gVHK!7bj-xR-749xSwT!kySpk6865U1vieBeMeQW4q6l07I1wbJVwlKqzNdwIW1ExDFx3ZtFaXxQMfTm4IAcUJ!8Lhus0c4XTQ6Ypn2jQFwjAtp0tFp20Im8HQTPRAIKyqzCL7CQ4afe7AXasqZY-ghio4XcpYfs1u4Otj7EGAVM4krlg~~"
	// Per revealed python script on server error, character replacement and base64 decoding
	decoded := b64d(token)

	// hex := hex.EncodeToString([]byte(decoded))
	// fmt.Println(hex)
	//
	// encoded := b64e(decoded)
	// fmt.Println(encoded)

	// Split decoded into a slice of 16 byte string blocks
	fmt.Printf("Length of decoded: %v\n", len(decoded))
	var cipherBlocks = make([]string, len(decoded)/BLOCKSIZE)
	// Loop and step 16
	// Initialize index, which is separate from iterator used in for loop
	var blockIdx int
	for i := 0; i < len(decoded); i += BLOCKSIZE {
		cipherBlocks[blockIdx] = decoded[i : i+BLOCKSIZE]
		fmt.Printf("%d: %x (length: %d)\n", blockIdx, cipherBlocks[blockIdx], len(cipherBlocks[blockIdx]))
		blockIdx++
	}

	// Since 10 blocks, 9 plaintexts (first one being initialization vector)
	plain := make([]string, 9)

	// TODO goroutine
	// TODO attack
	for i := 0; i < 9; i++ {
		attack(i, cipherBlocks, plain)
	}

	var plaintext string
	for i, _ := range plain {
		plaintext += string(plain[i])
	}

	fmt.Println(plaintext)

}

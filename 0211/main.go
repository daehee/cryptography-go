package main

import (
	"cryptography-go/utils"
	"fmt"
	"strings"
)

func main() {
	// plaintext := "YELLOW SUBMARINE"
	// dat, _ := ioutil.ReadFile("11.txt")
	// Feed 43As to guarantee mode detection: http://blog.joshuahaddad.com/cryptopals-challenge-11-aes/
	dat := strings.Repeat("A", 43)
	key := utils.RandBytes(16)
	ciphertext := utils.EncOracle([]byte(dat), key)
	// Detect ECB mode!
	if utils.DetectECB(ciphertext, len(key)) {
		fmt.Println("[!] Detected ECB mode repetition!")
	} else {
		fmt.Println("[!] Mode detection failed!")
	}
}

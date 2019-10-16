package main

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	key := []byte("YELLOW SUBMARINE")

	dat, _ := ioutil.ReadFile("7.txt")
	ciphertext, _ := base64.StdEncoding.DecodeString(string(dat))

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create the AES cipher: %s", err)
	}
	if len(ciphertext) < aes.BlockSize {
		log.Fatalf("Ciphertext block size is too short!")
	}

	plaintext := make([]byte, len(ciphertext))

	for bs, be := 0, aes.BlockSize; bs < len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		c.Decrypt(plaintext[bs:be], ciphertext[bs:be])
		// fmt.Printf("block %d to %d\n", bs, be)
		// fmt.Println(string(plaintext[bs:be]))
		// fmt.Println("")
	}

	fmt.Println(string(plaintext))

}
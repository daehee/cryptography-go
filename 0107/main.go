package main

import (
	"cryptography-go/utils"
	"encoding/base64"
	"fmt"
	"io/ioutil"
)

func main() {
	key := []byte("YELLOW SUBMARINE")
	dat, _ := ioutil.ReadFile("7.txt")

	ciphertext, _ := base64.StdEncoding.DecodeString(string(dat))
	plaintext := utils.DecryptAES128ECB(ciphertext, key)

	fmt.Println(string(plaintext))

	err := ioutil.WriteFile("7_decrypted.txt", plaintext, 0644)
	if err != nil {
		panic(err)
	}
}

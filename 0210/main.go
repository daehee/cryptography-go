package main

import (
	"cryptography-go/utils"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func main() {
	dat, _ := ioutil.ReadFile("10.txt")
	dat, err := base64.StdEncoding.DecodeString(string(dat))
	if err != nil {
		log.Fatal(err)
	}
	key := []byte("YELLOW SUBMARINE22")
	iv := []byte(strings.Repeat("\x00", len(key)))
	// ciphertext := utils.EncryptAES128CBC(dat, key, iv)
	plaintext := utils.DecryptAES128CBC(dat, key, iv)
	fmt.Println(string(plaintext))
}

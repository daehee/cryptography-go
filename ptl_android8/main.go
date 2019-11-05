package main

import (
	"crypto/md5"
	"cryptography-go/utils"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
	"regexp"
	"strconv"
)

func main() {
	// Ciphertext: G38zckAufW4B9A6sywz28kzgW8CCx1UWugLUTjKlo/kwV1CVesmr0tPX/JZOW0aik0TlkrcAIZZ/G0BigUtmeg==
	// IV: 706b1b2baadc64e532cc7c5655be1090
	// PIN: MD5 hash of 4 digits as string \d\d\d\d
	ciphertext := "G38zckAufW4B9A6sywz28kzgW8CCx1UWugLUTjKlo/kwV1CVesmr0tPX/JZOW0aik0TlkrcAIZZ/G0BigUtmeg=="
	// Key string from https://pentesterlab.com/android08/keys.json
	keyStr := "<=== P3nt3st3rL4b ===>"
	dat, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	iv, err := hex.DecodeString("1b7f3372402e7d6e01f40eaccb0cf6f2")
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.OpenFile("decrypted.txt",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	// Hack: detect using regex of PentesterLab's flag format
	rFlag := regexp.MustCompile(`\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`)
	// Iterate over every possible combination of \d\d\d\d as MD5 hash
	// TODO display numbers < 1000 as 4 digits
	for i := 0; i < 10000; i++ {
		num := strconv.Itoa(i)
		key := md5.Sum([]byte(keyStr + num))
		plaintext := utils.DecryptAES128CBC(dat, key[:], iv)
		// write lines to text file
		if rFlag.MatchString(string(plaintext)) {
			if _, err := f.WriteString(strconv.Itoa(i) + ": " + string(plaintext) + "\n"); err != nil {
				log.Println(err)
			}
		}
	}
}

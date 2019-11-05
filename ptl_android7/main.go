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
	// Ciphertext: ED1nf3uLW4Hkwr1aGw+NpN5sgcRMPCFuk0XgtW181m4o6d0Ml3D/j6h1NSyOh4dbcGsbK6rcZOUyzHxWVb4QkA
	// IV: 706b1b2baadc64e532cc7c5655be1090
	// PIN: MD5 hash of 4 digits as string \d\d\d\d
	ciphertext := "ED1nf3uLW4Hkwr1aGw+NpN5sgcRMPCFuk0XgtW181m4o6d0Ml3D/j6h1NSyOh4dbcGsbK6rcZOUyzHxWVb4QkA"
	dat, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	// iv, err := hex.DecodeString("706b1b2baadc64e532cc7c5655be1090")
	iv, err := hex.DecodeString("103d677f7b8b5b81e4c2bd5a1b0f8da4")
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
		key := md5.Sum([]byte(num))
		plaintext := utils.DecryptAES128CBC(dat, key[:], iv)
		// write lines to text file
		if rFlag.MatchString(string(plaintext)) {
			if _, err := f.WriteString(strconv.Itoa(i) + ": " + string(plaintext) + "\n"); err != nil {
				log.Println(err)
			}
		}
	}
}

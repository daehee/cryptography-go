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

const target = "http://ptl-7e09c62c-016c7d26.libcurl.so/"

func extractSig(token string) []byte {
	token, _ = url.QueryUnescape(token)
	decoded, _ := base64.RawStdEncoding.DecodeString(token)
	sig := strings.Split(string(decoded), "--")
	return []byte(sig[1])
}

func captureAuth(username string) (string, error) {
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

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "auth" {
			fmt.Println("Found auth cookie :", cookie.Value)
			return cookie.Value, nil
		}
	}
	return "", errors.New("Found no auth cookie")
}

func win(token string) (string, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		log.Fatalln(err)
	}

	req.AddCookie(&http.Cookie{Name: "auth", Value: token})

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

func makeAdminToken(m1, m2 string, t2 []byte) string {
	concat := "administrator--" + string(t2)
	encoded := base64.RawStdEncoding.EncodeToString([]byte(concat))
	return encoded
}

func main() {
	m1 := "administ"
	fmt.Println("[*] Capturing first token")
	token1, err := captureAuth(m1)
	if err != nil {
		log.Fatalln(err)
	}

	t1 := extractSig(token1)
	// fmt.Println(t1)
	m2 := "rator\x00\x00\x00"
	// XOR signature (t1) with m2, and use that as username value
	m2New := utils.XORBytes(t1, []byte(m2))
	fmt.Println("[*] Calculating new username (m2):")
	fmt.Printf("%x (hex)\n", m2New)
	fmt.Println("[*] Capturing second token")
	token2, err := captureAuth(string(m2New))
	if err != nil {
		log.Fatalln(err)
	}
	t2 := extractSig(token2)
	// Concatenate m and m' to get administrator and use t' as signature.
	adminToken := makeAdminToken(m1, m2, t2)
	fmt.Println("[*] Calculating admin token:")
	fmt.Println(adminToken)
	res, _ := win(adminToken)
	fmt.Println("[*] Final output:")
	fmt.Println(res)
}

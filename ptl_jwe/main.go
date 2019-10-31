package main

import (
	"cryptography-go/utils"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

func main() {
	// Read public key file
	publicKeyPath := ("public.pem")
	encrypter := initEncrypter(publicKeyPath)

	// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	var plaintext = []byte(`{"user":"admin"}`)
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}

	// fmt.Println(object.FullSerialize())
	fmt.Println(object.CompactSerialize())
}

// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
// indicate that the selected algorithm(s) are not currently supported.
func initEncrypter(keyPath string) jose.Encrypter {
	publicKey := utils.LoadRSAPublicKey(keyPath)
	// From test cookie: {"alg":"RSA-OAEP","enc":"A192GCM"}
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		panic(err)
	}
	return encrypter
}

package utils

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func LoadRSAPublicKey(keyPath string) interface{} {
	privKeyFile, err := os.Open(keyPath)
	fatal(err)

	pemfileinfo, _ := privKeyFile.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode(pembytes)
	privKeyFile.Close()

	keyImported, err := x509.ParsePKIXPublicKey(data.Bytes)
	fatal(err)
	return keyImported
}

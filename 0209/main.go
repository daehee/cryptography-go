package main

import (
	"cryptography-go/utils"
	"fmt"
)

func main() {
	blockLength := 20
	plaintext := "YELLOW SUBMARINE"
	padByte := "\x04"
	res := utils.PadPKCS7([]byte(plaintext), []byte(padByte), blockLength)
	fmt.Printf("Plaintext:\t%v\nPadded:\t\t%v", []byte(plaintext), res)
}

package main

import "fmt"

func pad(plaintext []byte, padByte []byte, blockLength int) []byte {
	diff := blockLength - (len(plaintext) % blockLength)
	padded := plaintext
	for i := 0; i < diff; i++ {
		padded = append(padded, padByte...)
	}
	return padded
}

func main() {
	blockLength := 20
	plaintext := "YELLOW SUBMARINE"
	padByte := "\x04"
	res := pad([]byte(plaintext), []byte(padByte), blockLength)
	fmt.Printf("Plaintext:\t%v\nPadded:\t\t%v", []byte(plaintext), res)
}

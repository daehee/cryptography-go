package main

import (
	"cryptography-go/utils"
	"encoding/hex"
	"fmt"
)

func main() {
	data := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

	// Loop through I, C, E as XOR key
	xorKeys := []rune{'I', 'C', 'E'}
	res := utils.XORWithKeys(data, xorKeys)

	fmt.Println(hex.EncodeToString([]byte(res)))

}

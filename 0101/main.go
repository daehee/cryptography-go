package main

import (
	"fmt"

	"github.com/daehee/cryptography-go/utils"
)

func main() {
	data := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	result := utils.HexToBase64(data)
	fmt.Println(result)
}


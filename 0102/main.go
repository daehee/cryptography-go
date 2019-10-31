package main

import (
	"cryptography-go/utils"
	"fmt"
)

func main() {
	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"

	result := utils.XorHex(a, b)

	fmt.Println(result)
}

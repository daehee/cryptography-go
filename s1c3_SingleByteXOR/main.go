package main

import (
	"encoding/hex"
	"fmt"

	"cryptography-go/utils"
)

func main() {
	data := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	b, _ := hex.DecodeString(data)

	ds := utils.Attack1XOR(b)
	res := utils.FindMax(ds)

	fmt.Printf("Plaintext: %s\nScore: %d\nKey: %s", res.Str, res.Count, string(res.Key))
}

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/daehee/cryptography-go/utils"
)

const MIN_SCORE = 23

func main() {
	data := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	b, _ := hex.DecodeString(data)

	for k := 0; k <= 255; k++ {
		decoded := utils.XorByte(b, byte(k))
		score := scoreText(decoded)
		if score > MIN_SCORE {
			fmt.Println(string(decoded))
			fmt.Println(score)
		}
	}
}

func scoreText(a []byte) int {
	count := 0
	for _, ch := range a {
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' {
			count++
		}
	}
	return count
}

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/daehee/cryptography-go/utils"
)

type decoded struct {
	str   string
	count int
}

func findMax(ds []decoded) string {
	max := ds[0]

	for _, d := range ds {
		if d.count > max.count {
			max = d
		}
	}
	return max.str
}

func main() {
	data := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	b, _ := hex.DecodeString(data)

	ds := make([]decoded, 256)

	for k := 0; k < 256; k++ {
		ds[k].str = string(utils.XorByte(b, byte(k)))
		// count number of spaces
		for _, v := range ds[k].str {
			if rune(v) == ' ' {
				ds[k].count++
			}
		}
	}

	res := findMax(ds)
	fmt.Println(res)

}

package main

import (
	"cryptography-go/utils"
	"fmt"
)

func main() {
	key := utils.RandBytes(16)
	unknown := utils.OracleUnknownString(key)
	fmt.Println("[*] Plaintext of unknown string:")
	fmt.Println(string(unknown))
}

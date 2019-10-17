package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

type result struct {
	ciphertext []byte
	repetitions int
	ln int
}

func uniqueChunks(chunks [][]byte) map[string]int {
	// create map and use hexencoded bytes as key
	dupes := make(map[string]int)
	for _, chunk := range chunks {
		h := hex.EncodeToString(chunk)
		_, exist := dupes[h]
		if exist {
			dupes[h]++
		} else {
			dupes[h] = 1
		}
	}
	return dupes
}

func buildChunks(ciphertext []byte, blockSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(ciphertext); i += blockSize {
		chunk := ciphertext[i:i+blockSize]
		chunks = append(chunks, chunk)
	}
	return chunks
}

func countRepeatedChunks(ciphertext []byte, blockSize int, ln int) result {
	repetitions := 0
	chunks := buildChunks(ciphertext, blockSize)
	unique := len(uniqueChunks(chunks))
	repetitions += len(chunks) - unique
	return result{ciphertext,repetitions, ln}
}

func findMax(results []result) result {
	mc := results[0].ciphertext
	mr := results[0].repetitions
	ml := results[0].ln
	for _, v := range results {
		if v.repetitions > mr {
			mc = v.ciphertext
			mr = v.repetitions
			ml = v.ln
		}
	}
	return result{mc, mr, ml}
}

func main() {
	file, _ := os.Open("8.txt")
	scanner := bufio.NewScanner(file)
	results := make([]result, 0)
	ln := 1
	for scanner.Scan() {
		ciphertext, _ := hex.DecodeString(scanner.Text())
		blockSize := 16
		results = append(results, countRepeatedChunks(ciphertext, blockSize, ln))
		ln++
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
	answer := findMax(results)
	fmt.Printf("Line number %d, %d repeating blocks", answer.ln, answer.repetitions)
}

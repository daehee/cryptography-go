package main

import (
	"bufio"
	"cryptography-go/utils"
	"encoding/hex"
	"fmt"
	"os"
)

type result struct {
	ciphertext  []byte
	repetitions int
	ln          int
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
		repetitions := utils.CountRepeatChunks(ciphertext, blockSize)
		results = append(results, result{ciphertext, repetitions, ln})
		ln++
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
	answer := findMax(results)
	fmt.Printf("Line number %d, %d repeating blocks", answer.ln, answer.repetitions)
}

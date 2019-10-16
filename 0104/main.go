package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"cryptography-go/utils"
)

// One of the 60-character strings in this file has been encrypted by single-character XOR.

func main() {
	// read text file
	file, err := os.Open("4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	ds := []utils.Decoded{}
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		// TODO test speed of launch a goroutine for each line
		s := sc.Text()
		// convert from hex
		b, _ := hex.DecodeString(s)
		ds = append(ds, utils.Attack1XOR(b)...)
	}
	res := utils.FindMax(ds)

	fmt.Printf("Plaintext: %s\nScore: %d\nKey: %s", res.Str, res.Count, string(res.Key))

}

package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"strings"

	tm "github.com/buger/goterm"
)

/*
def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted
*/

// Arbitrary decrypt function as defined in victim script
func decrypt(text, key string) string {
	keyLen := len(key)
	keyPos := 0
	var decrypted string
	for _, c := range text {
		keyChr := key[keyPos]
		newChr := int(c)
		newChr2 := string((newChr - int(keyChr)) % 255)
		decrypted += newChr2
		keyPos += 1
		keyPos = keyPos % keyLen
	}
	return decrypted
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	// Parse arg flag to read wordlist of keys
	flag.Parse()
	wordlistFile := flag.Arg(0)

	var err error
	var data []byte

	// Exfiltrate base64 encoded DECRYPTED text as check.txt
	data, err = ioutil.ReadFile("check.txt")
	check(err)
	solution, err := base64.StdEncoding.DecodeString(string(data))
	check(err)

	// Exfiltrated base64 encoded ENCRYPTED text as out.txt
	data, err = ioutil.ReadFile("out.txt")
	check(err)
	encrypted, err := base64.StdEncoding.DecodeString(string(data))
	check(err)

	var f io.Reader
	f, err = os.Open(wordlistFile)
	check(err)

	tm.Clear() // Clear current screen

	var cnt int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key := sc.Text()
		// Empty lines in wordlist cause panic
		if len(key) == 0 {
			continue
		}

		// goterm stuff
		tm.MoveCursor(1, 1)
		tm.Println(cnt)
		tm.Flush() // Call it every time at the end of rendering

		dd := decrypt(string(encrypted), key)
		// Trim whitespace to match correctly
		if strings.TrimSpace(string(solution)) == strings.TrimSpace(dd) {
			tm.MoveCursor(1, 1)
			tm.Println(key)
			tm.Flush() // Call it every time at the end of rendering
			break
		}
		cnt++
	}

}

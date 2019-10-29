package utils

import (
	"crypto/aes"
	"encoding/hex"
	"log"
)

func CountRepeatChunks(ciphertext []byte, blockSize int) int {
	repetitions := 0
	chunks := BuildChunks(ciphertext, blockSize)
	unique := len(uniqueChunks(chunks))
	repetitions += len(chunks) - unique
	return repetitions
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

func BuildChunks(ciphertext []byte, blockSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(ciphertext); i += blockSize {
		chunk := ciphertext[i : i+blockSize]
		chunks = append(chunks, chunk)
	}
	return chunks
}

func PadPKCS7(plaintext []byte, padByte []byte, blockSize int) []byte {
	diff := blockSize - (len(plaintext) % blockSize)
	padded := plaintext
	for i := 0; i < diff; i++ {
		padded = append(padded, padByte...)
	}
	return padded
}

// func PadTo(buffer []byte, blockSize int) int {
// 	padSize := blockSize - (len(buffer) % blockSize)
// 	return padSize
// }

func DecryptAES128ECB(buffer, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create the AES cipher: %s", err)
	}
	if len(buffer) < aes.BlockSize {
		log.Fatalf("Ciphertext block size is too short!")
	}
	if len(buffer)%aes.BlockSize != 0 {
		panic("buffer should be a multiple of blocksize")
	}

	plaintext := make([]byte, len(buffer))
	for i := 0; i < len(buffer); i += aes.BlockSize {
		c.Decrypt(plaintext[i:i+aes.BlockSize], buffer[i:i+aes.BlockSize])
	}
	return plaintext
}

func EncryptAES128ECB(buffer, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create the AES cipher: %s", err)
	}
	if len(buffer) < aes.BlockSize {
		log.Fatalf("Plaintext block size is too short!")
	}
	if len(buffer)%aes.BlockSize != 0 {
		panic("buffer should be a multiple of blocksize")
	}

	ciphertext := make([]byte, len(buffer))
	for i := 0; i < len(buffer); i += aes.BlockSize {
		c.Encrypt(ciphertext[i:i+aes.BlockSize], buffer[i:i+aes.BlockSize])
	}
	return ciphertext
}

func DecryptAES128CBC(buffer, key, iv []byte) []byte {
	blockSize := len(key)
	prevBlock := iv
	var plaintext []byte
	for bs, be := 0, blockSize; bs < len(buffer); bs, be = bs+blockSize, be+blockSize {
		decBlock := DecryptAES128ECB(buffer[bs:be], key)
		xored := XORBytes(decBlock, prevBlock)
		// set previous block to encrypted block
		prevBlock = buffer[bs:be]
		plaintext = append(plaintext, xored...)
	}
	return plaintext
}

func EncryptAES128CBC(buffer, key, iv []byte) []byte {
	// pad plaintext to blocksize
	padByte := []byte("\x04")
	blockSize := len(key)
	buffer = PadPKCS7(buffer, padByte, blockSize)

	var ciphertext []byte
	// set previous block as IV
	prevBlock := iv
	for bs, be := 0, blockSize; bs < len(buffer); bs, be = bs+blockSize, be+blockSize {
		// XOR current block with previous block
		xored := XORBytes(buffer[bs:be], prevBlock)
		// then AES encrypt the XORed block
		encBlock := EncryptAES128ECB(xored, key)
		// set previous block to encrypted block
		prevBlock = encBlock
		ciphertext = append(ciphertext, encBlock...)
	}
	return ciphertext
}

func DetectECB(buffer []byte, blockSize int) bool {
	repetitions := CountRepeatChunks(buffer, blockSize)
	isECB := false
	if repetitions > 0 {
		isECB = true
	}
	return isECB
}

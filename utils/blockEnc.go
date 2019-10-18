package utils

import (
	"crypto/aes"
	"log"
)

func PadPKCS7(plaintext []byte, padByte []byte, blockLength int) []byte {
	diff := blockLength - (len(plaintext) % blockLength)
	padded := plaintext
	for i := 0; i < diff; i++ {
		padded = append(padded, padByte...)
	}
	return padded
}

func DecryptAES128ECB(buffer, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create the AES cipher: %s", err)
	}
	if len(buffer) < aes.BlockSize {
		log.Fatalf("Ciphertext block size is too short!")
	}

	plaintext := make([]byte, len(buffer))
	for bs, be := 0, aes.BlockSize; bs < len(buffer); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		c.Decrypt(plaintext[bs:be], buffer[bs:be])
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

	ciphertext := make([]byte, len(buffer))
	for bs, be := 0, aes.BlockSize; bs < len(buffer); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		c.Encrypt(ciphertext[bs:be], buffer[bs:be])
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

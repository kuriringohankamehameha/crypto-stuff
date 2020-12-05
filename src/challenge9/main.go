package main

import (
	"fmt"
)

func addPadding(input []byte, blockSize int, paddingCharacter rune) ([]byte, int) {
	paddingSize := blockSize - (len(input) % blockSize)
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingCharacter)
	}
	input = append(input, padding...)
	return input, paddingSize
}

func addPKCSPadding(input []byte, blockSize int) ([]byte, int) {
	const char = '\x04'
	return addPadding(input, blockSize, rune(char))
}

func main() {
	key := []byte("YELLOW SUBMARINE")
	processed, _ := addPKCSPadding(key, len(key)+4)
	fmt.Println("Padded input:", processed[:], ", string:", string(processed))
}

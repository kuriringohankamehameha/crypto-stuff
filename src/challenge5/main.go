package main

import (
	"encoding/hex"
	"fmt"
)

func encryptRepeatingXOR(input string, key string) []byte {
	// Applies the repeating XOR key on the input string, and encodes to hex
	byteInput, byteKey := []byte(input), []byte(key)
	keySize := len(byteKey)
	encrypted := make([]byte, len(byteInput))
	hexEncrypted := make([]byte, hex.EncodedLen(len(byteInput)))
	for i := range byteInput {
		a := byteInput[i]
		b := byteKey[i%keySize]
		encrypted[i] = a ^ b
	}
	hex.Encode(hexEncrypted, encrypted)
	return hexEncrypted
}

func main() {
	encrypted := encryptRepeatingXOR("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
	fmt.Println("Repeating XOR Encrpytion:", string(encrypted))
}

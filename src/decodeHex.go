package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

func hextoBase64(input []byte) ([]byte, int) {
	// Decodes a hex input and converts into base64
	output := make([]byte, hex.DecodedLen(len(input)))
	numDecoded, err := hex.Decode(output, input)
	if err != nil {
		log.Fatal(err)
	}
	base64Encoded := make([]byte, base64.StdEncoding.EncodedLen(numDecoded))
	base64.StdEncoding.Encode(base64Encoded, output) // Encode to base64
	return base64Encoded, len(base64Encoded)
}

func decodeHex(input []byte) ([]byte, int) {
	// Decodes a hex input into a byte slice
	output := make([]byte, hex.DecodedLen(len(input)))
	numDecoded, err := hex.Decode(output, input)
	if err != nil {
		log.Fatal(err)
	}
	return output, numDecoded
}

func max(a int, b int) int {
	if a >= b {
		return a
	} else {
		return b
	}
}

func xor(a []byte, b []byte) []byte {
	// Performs a bitwise XOR
	var minSlice, maxSlice []byte
	if len(a) >= len(b) {
		maxSlice = a
		minSlice = b
	} else {
		maxSlice = b
		minSlice = a
	}
	result := make([]byte, len(maxSlice))
	for i := range maxSlice {
		bytea := maxSlice[i]
		var byteb byte
		if i >= len(minSlice) {
			byteb = byte(0)
		} else {
			byteb = minSlice[i]
		}
		result[i] = bytea ^ byteb
	}
	return result
}

func fixedXorDecrypt(input []byte, mask []byte) ([]byte, int) {
	// Decrypts a hex input using a mask key via a bitwise XOR
	decodedInput, n := decodeHex(input)
	decodedMask, m := decodeHex(mask)
	return xor(decodedInput, decodedMask), max(n, m)
}

func getFrequencies(decoded []byte, plaintext []byte) []map[byte]int {
	// Accumulates the frequencies of every occuring character across the set of possible keys (English letters)
	frequencies := make([]map[byte]int, len(plaintext))
	for i := range frequencies {
		frequencies[i] = make(map[byte]int)
	}

	for i := range plaintext {
		key := bytes.Repeat(plaintext[i:i+1], len(plaintext)) // Single character key must be repeated
		decrypted := xor(decoded, key)
		// fmt.Println("For key:", string(plaintext[i]), "Decoded:", string(decrypted))
		for j := range decrypted {
			if decrypted[j] == plaintext[i] {
				// Likely empty. So we skip it to avoid unnecessary counting of the key itself
				continue
			}
			_, ok := frequencies[i][decrypted[j]]
			if ok == false {
				frequencies[i][decrypted[j]] = 1
			} else {
				frequencies[i][decrypted[j]] += 1
			}
		}
	}
	return frequencies
}

func decryptXorCipher(hexEncrypted []byte, keySize int) ([]byte, int) {
	// Decrypts a hex-encrypted string, assuming that it has been XORd with a key of size `keySize` bytes
	// ASSUMPTION: The string alphabet consists only of English plaintext letters
	decoded, n := decodeHex(hexEncrypted)
	var decrypted []byte
	plaintext := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	frequencies := getFrequencies(decoded, plaintext)
	scores := make([]int, len(frequencies))
	for i := range frequencies {
		commonLetters := "aeiourstnyd"
		for j := range commonLetters {
			frequency, ok := frequencies[i][commonLetters[j]]
			if ok == false {
				continue
			} else {
				scores[i] += frequency
			}
		}
	}

	// We finally pick the byte-string with the maximum score
	// If there are multiple candidates, the last candidate is chosen
	maxScore := 0
	for i := range scores {
		if scores[i] >= maxScore {
			maxScore = scores[i]
			key := bytes.Repeat(plaintext[i:i+1], n) // Single character key must be repeated
			decrypted = xor(decoded, key)
			// fmt.Println("For character", string(plaintext[i]), ": Decrypted =", string(decrypted))
		}
	}
	return decrypted, n
}

func main() {
	inputbyteString := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	decodedbyteString, n1 := hextoBase64(inputbyteString)

	fmt.Println("Input Hex String:", string(inputbyteString))
	fmt.Println("Encoded Base64 String:", string(decodedbyteString[:n1]))

	mask := []byte("686974207468652062756c6c277320657965")
	maskedOutput, n2 := fixedXorDecrypt([]byte("1c0111001f010100061a024b53535009181c"), mask)

	fmt.Println("XOR against mask", string(mask), ":", string(maskedOutput[:n2]))

	xorAnswer, _ := decodeHex([]byte("746865206b696420646f6e277420706c6179"))

	if string(maskedOutput[:n2]) != string(xorAnswer) {
		log.Panic("Wrong answer")
	}

	decryptedAnswer, n3 := decryptXorCipher([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), 1)
	fmt.Println("Single Byte XOR Decryption:", string(decryptedAnswer[:n3]))
}

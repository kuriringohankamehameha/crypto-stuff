package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
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

func generateKey(alphabet []byte, position int, numBytes int, keySize int) []byte {
	return bytes.Repeat(alphabet[position:position+numBytes], keySize/numBytes)
}

func getFrequencies(decoded []byte, plaintext []byte, numBytes int) []map[byte]int {
	// Accumulates the frequencies of every occuring character across the set of possible keys (English letters)
	frequencies := make([]map[byte]int, len(plaintext))
	for i := range frequencies {
		frequencies[i] = make(map[byte]int)
	}

	for i := range plaintext {
		key := generateKey(plaintext, i, numBytes, len(decoded))
		decrypted := xor(decoded, key)
		// fmt.Println("For key:", string(plaintext[i]), "Decoded:", string(decrypted))
		for j := range decrypted {
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

func decryptXorCipher(hexEncrypted []byte, numBytes int) ([]byte, int) {
	// Decrypts a hex-encrypted string, assuming that it has been XORd with a key of size `keySize` bytes
	// ASSUMPTION: The string alphabet consists only of English plaintext letters
	decoded, n := decodeHex(hexEncrypted)
	var decrypted []byte
	plaintext := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	englishFrequencies := map[string]float64{
		"a": 8.167,
		"b": 1.492,
		"c": 2.782,
		"d": 4.253,
		"e": 12.702,
		"f": 2.228,
		"g": 2.015,
		"h": 6.094,
		"i": 6.966,
		"j": 0.153,
		"k": 0.772,
		"l": 4.025,
		"m": 2.406,
		"n": 6.749,
		"o": 7.507,
		"p": 1.929,
		"q": 0.095,
		"r": 5.987,
		"s": 6.327,
		"t": 9.056,
		"u": 2.758,
		"v": 0.978,
		"w": 2.360,
		"x": 0.150,
		"y": 1.974,
		"z": 0.074,
		" ": 20.000, // Priority to spaces
	}
	commonLetters := make([]byte, 0)
	for i := range englishFrequencies {
		commonLetters = append(commonLetters, []byte(i)...)
	}

	scores := make(map[byte]float64)
	for i := range plaintext {
		key := generateKey(plaintext, i, 1, len(hexEncrypted))
		decrypted := xor(decoded, key)
		for j := range decoded {
			_, ok := englishFrequencies[string(decrypted[j])]
			if ok == true {
				_, ok := scores[plaintext[i]]
				if ok == false {
					scores[key[0]] = englishFrequencies[strings.ToLower(string(decrypted[j]))]
				} else {
					scores[key[0]] += englishFrequencies[strings.ToLower(string(decrypted[j]))]
				}
			} else {
			}
		}
	}

	/*
		for i := range scores {
			fmt.Println("Key:", string(i), " -> Value:", scores[i], "Decoded:", string(xor(decoded, bytes.Repeat([]byte(string(i)), len(decoded)))))
		}
	*/

	// We finally pick the byte-string with the maximum score
	// If there are multiple candidates, the last candidate is chosen
	maxScore := 0.0
	for i := range plaintext {
		_, ok := scores[plaintext[i]]
		if ok == false {
			continue
		}
		if scores[plaintext[i]] >= maxScore {
			maxScore = scores[plaintext[i]]
			key := generateKey(plaintext, i, numBytes, n)
			decrypted = xor(decoded, key)
			// fmt.Println("For character", string(plaintext[i]), ": Decrypted =", string(decrypted))
		}
	}
	return decrypted, n
}

func main() {
	decryptedAnswer, n := decryptXorCipher([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), 1)
	fmt.Println("Single Byte XOR Decryption:", string(decryptedAnswer[:n]))
}

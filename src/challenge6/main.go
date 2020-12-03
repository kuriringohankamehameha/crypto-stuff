package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"sort"
	"strings"
)

func min(a float64, b float64) float64 {
	if a <= b {
		return a
	} else {
		return b
	}
}

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
		//return []byte(""), 0
		log.Fatal("Error while decoding hex:\n", err)
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

func decryptXorCipher(hexEncrypted []byte, numBytes int) ([]byte, int, byte, float64) {
	// Decrypts a hex-encrypted string, assuming that it has been XORd with a key of size `keySize` bytes
	decoded, n := decodeHex(hexEncrypted)
	plaintext := make([]byte, 256)
	for i := 0; i < 256; i++ {
		plaintext[i] = byte(i)
	}
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
		" ": 25.000, // Priority to spaces
	}

	scores := make(map[byte]float64)
	for i := range plaintext {
		key := generateKey(plaintext, i, 1, len(decoded))
		decrypted := xor(decoded, key)
		for j := range decrypted {
			_, ok := englishFrequencies[strings.ToLower(string(decrypted[j]))]
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

	// We finally pick the byte-string with the maximum score
	// If there are multiple candidates, the last candidate is chosen
	maxScore := 0.0
	var decrypted []byte
	var key []byte
	for i := range plaintext {
		_, ok := scores[plaintext[i]]
		if ok == false {
			continue
		}
		if scores[plaintext[i]] >= maxScore {
			maxScore = scores[plaintext[i]]
			key = generateKey(plaintext, i, numBytes, len(decoded))
			decrypted = xor(decoded, key)
		}
	}
	return decrypted, n, key[0], maxScore
}

func decodeBase64(input []byte) []byte {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	_, err := base64.StdEncoding.Decode(output, input)
	if err != nil {
		log.Fatal(err)
	}
	return output
}

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

func computeHammingDistance(a []byte, b []byte) int {
	// Gives the number of different BITS
	distance := 0
	if len(a) != len(b) {
		log.Fatal("Strings must have equal length to compute hamming distance")
	}
	for i := range a {
		for j := 0; j < 8; j++ {
			bita := a[i] & (1 << j)
			bitb := b[i] & (1 << j)
			if bita != bitb {
				distance++
			}
		}
	}
	return distance
}

func estimateKeySizes(data []byte, limit int) []int {
	// Tries to estimate the key size
	// Gives the top N candidate key sizes
	distances := make(map[int]float64)

	NUM_BLOCKS := 4
	TOP_N := 4

	buffer := make([]int, TOP_N)

	for keysize := 1; keysize <= limit; keysize++ {
		totalDistance := 0.0
		blocks := 0
		for i := 0; i <= 2*keysize*NUM_BLOCKS; i += 2 * keysize {
			blocks++
			if i+(2*keysize) >= len(data) {
				break
			}
			a := data[i : i+keysize]
			b := data[i+keysize : i+(2*keysize)]
			if len(a) != len(b) {
				continue
			}
			distance := computeHammingDistance(a, b)
			normalizedDistance := float64(distance) / float64(keysize)
			if normalizedDistance == 0 {
				fmt.Println(normalizedDistance, keysize)
			}
			totalDistance += normalizedDistance
		}
		distances[keysize] = float64(totalDistance) / float64(blocks)
	}

	values := make([]float64, 0)
	keys := make(map[float64]int, 0)
	for k, _ := range distances {
		values = append(values, distances[k])
		keys[distances[k]] = k
	}
	sort.Float64s(values)
	for i := range values[:TOP_N] {
		buffer[i] = keys[values[i]]
		//fmt.Println(keys[values[i]], values[i])
	}
	return buffer
}

func transposeBlocks(data []byte, keySize int) [][]byte {
	// Divide the data into blocks, based on the key
	// so that a single bit XOR decryption can be done on each of these blocks
	blocks := make([][]byte, keySize)
	for i := 0; i < keySize; i++ {
		idx := 0
		result := make([]byte, 1+len(data)/keySize)
		for j := i; j < len(data); j += keySize {
			result[idx] = data[j]
			idx++
		}
		blocks[i] = result
	}
	return blocks
}

func getDecryptionKeys(data []byte, keySizes []int) ([][]byte, int) {
	// From the candidate keys, find the key with the maximum score
	TOP_N := 4
	decryptedKeys := make([][]byte, TOP_N)
	scores := make([]float64, TOP_N)
	idx := 0
	maxScore := float64(0.0)
	for i := range keySizes {
		decryptedKeys[i] = make([]byte, keySizes[i])
		keysize := keySizes[i]
		blocks := transposeBlocks(data, keysize)
		for j := range blocks {
			hexEncrypted := make([]byte, hex.EncodedLen(len(blocks[j])))
			hex.Encode(hexEncrypted, blocks[j])
			_, _, key, score := decryptXorCipher(hexEncrypted, 1)
			decryptedKeys[i][j] = key
			scores[i] += score
		}
	}
	for i := range scores {
		if scores[i] > maxScore {
			maxScore = scores[i]
			idx = i
		}
	}
	return decryptedKeys, idx
}

func decryptData(data []byte, key []byte) []byte {
	// Decrypt the data with the key which we just obtained finally
	result := make([]byte, len(data))
	keysize := len(key)
	for i := 0; i < len(data); i += 1 {
		result[i] = data[i] ^ key[i%keysize]
	}
	return result
}

func main() {
	// data is base64'd after being encrypted with repeating-key XOR.
	data, err := ioutil.ReadFile(path.Join("src/challenge6", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	processed := decodeBase64(data)
	distance := computeHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if distance != 37 {
		log.Panic("Incorrect hamming distance")
	}
	keySizes := estimateKeySizes(processed, 40)
	//fmt.Println(keySizes)
	decryptedKeys, idx := getDecryptionKeys(processed, keySizes)
	fmt.Printf("Decrypted Key = '%s'\n", string(decryptedKeys[idx]))
	key := decryptedKeys[idx]
	result := decryptData(processed, key)
	fmt.Println(string(result))
}

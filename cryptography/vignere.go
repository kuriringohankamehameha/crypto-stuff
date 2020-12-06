package cryptography

import (
	"encoding/hex"
	"sort"
	"strings"
)

func DecryptVignere(data []byte, maxKeysize int) []byte {
	// Tries to decrypt a vignere cipher using the Kasiski examination
	keySizes := estimateKeySizes(data, maxKeysize)
	decryptedKeys, idx := getDecryptionKeys(data, keySizes)
	key := decryptedKeys[idx]
	result := decryptData(data, key)
	return result
}

func EncryptVignere(input string, key string) []byte {
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

func fixedXorDecrypt(input []byte, mask []byte) ([]byte, int) {
	// Decrypts a hex input using a mask key via a bitwise XOR
	decodedInput, n := DecodeHex(input)
	decodedMask, m := DecodeHex(mask)
	return Xor(decodedInput, decodedMask), Intmax(n, m)
}

func decryptXorCipher(hexEncrypted []byte, numBytes int) ([]byte, int, byte, float64) {
	// Decrypts a hex-encrypted string, assuming that it has been XORd with a key of size `keySize` bytes
	decoded, n := DecodeHex(hexEncrypted)
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
		key := GenerateKey(plaintext, i, 1, len(decoded))
		decrypted := Xor(decoded, key)
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
			key = GenerateKey(plaintext, i, numBytes, len(decoded))
			decrypted = Xor(decoded, key)
		}
	}
	return decrypted, n, key[0], maxScore
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
			distance := HammingDistance(a, b)
			normalizedDistance := float64(distance) / float64(keysize)
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

func decryptData(data []byte, key []byte) []byte {
	// Decrypt the data with the key which we just obtained finally
	result := make([]byte, len(data))
	keysize := len(key)
	for i := 0; i < len(data); i += 1 {
		result[i] = data[i] ^ key[i%keysize]
	}
	return result
}

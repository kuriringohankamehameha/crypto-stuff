package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"path"
	"sort"
	"strings"
	"time"
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
		log.Fatal("Error while decoding hex:\n", err)
	}
	return output, numDecoded
}

func Intmax(a int, b int) int {
	if a >= b {
		return a
	} else {
		return b
	}
}

func Intmin(a int, b int) int {
	if a <= b {
		return a
	} else {
		return b
	}
}

func decodeBase64(input []byte) []byte {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	_, err := base64.StdEncoding.Decode(output, input)
	if err != nil {
		log.Fatal(err)
	}
	return output
}

func addPadding(input []byte, blockSize int) ([]byte, int) {
	paddingSize := blockSize - (len(input) % blockSize)
	padding := make([]byte, paddingSize)
	input = append(input, padding...)
	return input, paddingSize
}

func encryptAESECB(input []byte, key []byte) ([]byte, error) {
	err := error(nil)
	cipher, _err := aes.NewCipher(key)
	blockSize := len(key)
	if _err != nil {
		return nil, err
	}
	if len(input) < blockSize {
		err = errors.New("Input size is too short")
		return nil, err
	}

	if len(input)%blockSize != 0 {
		err = errors.New("Input must be a multiple of the block size")
		return nil, err
	}

	// Divide the input into blocks and decrypt it
	encrypted := make([]byte, len(input))

	for offset := 0; offset < len(input); offset += blockSize {
		cipher.Encrypt(encrypted[offset:offset+blockSize], input[offset:offset+blockSize])
	}
	return encrypted, nil
}

func DecryptAESECB(input []byte, key []byte) ([]byte, error) {
	err := error(nil)
	cipher, _err := aes.NewCipher(key)
	blockSize := len(key)
	if _err != nil {
		return nil, err
	}
	if len(input) < blockSize {
		err = errors.New("Input size is too short")
		return nil, err
	}

	if len(input)%blockSize != 0 {
		err = errors.New("Input must be a multiple of the block size")
		return nil, err
	}

	// Divide the input into blocks and decrypt it
	decrypted := make([]byte, len(input))

	for offset := 0; offset < len(input); offset += blockSize {
		cipher.Decrypt(decrypted[offset:offset+blockSize], input[offset:offset+blockSize])
	}
	return decrypted, nil
}

func getWords(data []byte) [][]byte {
	words := make([][]byte, 0)
	for _, m := range strings.Split(string(data), "\n") {
		mbyte := decodeBase64([]byte(m))
		if len(mbyte) == 0 {
			continue
		}
		words = append(words, mbyte[:len(mbyte)-1])
	}
	return words
}

func getRandomKey(n int) []byte {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return b
}

func getRepetitionMap(words [][]byte, keySize int) map[int]int {
	repetitionMap := map[int]int{}
	for i := range words {
		word := words[i]
		repetitionMap[i+1] = simulateECB(word, keySize)
	}
	return repetitionMap
}

func rankMap(values map[int]int) []int {
	type kv struct {
		Key   int
		Value int
	}
	var ss []kv
	for k, v := range values {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})
	ranked := make([]int, len(values))
	for i, kv := range ss {
		ranked[i] = kv.Key
	}
	return ranked
}

func getMaxRepetitions(repetitionMap map[int]int) (int, int) {
	ranks := rankMap(repetitionMap)
	return ranks[0], repetitionMap[ranks[0]]
}

func runningtime(s string) (string, time.Time) {
	log.Println("Start:	", s)
	return s, time.Now()
}

func track(s string, startTime time.Time) {
	endTime := time.Now()
	log.Println("End:	", s, "took", endTime.Sub(startTime))
}

func simulateECB(cipherText []byte, keySize int) int {
	// Finds the number of ciphertext repetitions
	// and tries to correlate the maximum repeating word to ECB encryption
	cipherTexts := make([][]byte, 0)

	cipherText, _ = addPadding(cipherText, keySize)
	repetitions := 0

	for i := 0; i < len(cipherText); i += keySize {
		for j := range cipherTexts {
			if string(cipherText[i:i+keySize]) == string(cipherTexts[j]) {
				repetitions++
			}
		}
		cipherTexts = append(cipherTexts, cipherText[i:i+keySize])
	}
	return repetitions
}

func testAESECB() {
	defer track(runningtime("AES Test Time"))
	input := []byte("This is a sample input consisting of more than required")
	key := []byte("ENCRYPTION KEYAB")
	input, paddingSize := addPadding(input, len(key))
	encrypted, _ := encryptAESECB(input, key)
	fmt.Println(string(encrypted))
	decrypted, _ := DecryptAESECB(encrypted, key)
	fmt.Println(string(decrypted[:len(decrypted)-paddingSize]))
}

func main() {
	// AES ECB - The same plaintext always gives the same ciphertext
	data, err := ioutil.ReadFile(path.Join("src/challenge8", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	words := getWords(data)
	repetitionMap := getRepetitionMap(words, 16)
	lineNumber, repetitions := getMaxRepetitions(repetitionMap)
	fmt.Println("Line number:", lineNumber, " has ECB: max repetitions:", repetitions)
}

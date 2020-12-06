package cryptography

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math/rand"
	"strings"
	"time"
)

func HextoBase64(input []byte) ([]byte, int) {
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

func DecodeHex(input []byte) ([]byte, int) {
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

func DecodeBase64(input []byte) []byte {
	output := make([]byte, base64.StdEncoding.DecodedLen(len(input)))
	_, err := base64.StdEncoding.Decode(output, input)
	if err != nil {
		log.Fatal(err)
	}
	return output
}

func AddPadding(input []byte, blockSize int, paddingCharacter rune) ([]byte, int) {
	paddingSize := blockSize - (len(input) % blockSize)
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingCharacter)
	}
	input = append(input, padding...)
	return input, paddingSize
}

func GenerateKey(alphabet []byte, position int, numBytes int, keySize int) []byte {
	// Generates a repeating key
	return bytes.Repeat(alphabet[position:position+numBytes], keySize/numBytes)
}

func GetRandomInteger(a int, b int) int {
	// Generates a random integer from [a, b]
	seed := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(seed)
	return a + rand.Intn(b-a)
}

func GetRandomByteString(n int) []byte {
	// Generates a random byte string
	seed := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(seed)
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return b
}

func Xor(input []byte, key []byte) []byte {
	// Applies the repeating XOR key on the input string, and encodes to hex
	byteInput, byteKey := []byte(input), []byte(key)
	keySize := len(byteKey)
	encrypted := make([]byte, len(byteInput))
	for i := range byteInput {
		a := byteInput[i]
		b := byteKey[i%keySize]
		encrypted[i] = a ^ b
	}
	return encrypted
}

func GetLines(filePath string) ([][]byte, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	words := getWords(data)
	return words, err
}

func getWords(data []byte) [][]byte {
	words := make([][]byte, 0)
	for _, m := range strings.Split(string(data), "\n") {
		mbyte := DecodeBase64([]byte(m))
		if len(mbyte) == 0 {
			continue
		}
		words = append(words, mbyte[:len(mbyte)-1])
	}
	return words
}

func HammingDistance(a []byte, b []byte) int {
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

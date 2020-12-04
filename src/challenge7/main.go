package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"path"
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

	// Divide the input into blocks and decrypt it
	decrypted := make([]byte, len(input))

	for offset := 0; offset < len(input); offset += blockSize {
		var padding []byte
		var size int
		if len(input)-offset < blockSize {
			padding = make([]byte, blockSize-len(input)+offset)
			size = len(input) - offset
		} else {
			padding = []byte{}
			size = blockSize
		}
		a := append(decrypted[offset:offset+size], padding...)
		b := append(input[offset:offset+size], padding...)
		cipher.Decrypt(a, b)
	}

	return decrypted, nil
}

func main() {
	// data is base64'd after being encrypted with repeating-key XOR.
	data, err := ioutil.ReadFile(path.Join("src/challenge7", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	processed := decodeBase64(data)
	decryptionKey := []byte("YELLOW SUBMARINE")
	processed = decodeBase64(data)
	decrypted, err := DecryptAESECB(processed, decryptionKey)
	if err != nil {
		log.Fatal("Error during decryption:\n", err)
	}
	result := decrypted
	fmt.Println("Decrypted:\n", string(result))
}

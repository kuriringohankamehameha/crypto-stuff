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

func addPadding(input []byte, blockSize int, paddingCharacter rune) ([]byte, int) {
	paddingSize := blockSize - (len(input) % blockSize)
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingCharacter)
	}
	input = append(input, padding...)
	return input, paddingSize
}

func xor(input []byte, key []byte) []byte {
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

func encryptAESCBC(input []byte, key []byte, IV []byte) ([]byte, error) {
	// Performs AES encryption in CBC mode
	// Here, the initial state is maintained by a random Initialization Vector (IV)
	// The flow is as follows: (Here, Pn represents the nth plaintext block, while Cn represents the nth ciphertext block)
	// C1 = Encrypt(P1 ^ IV)
	// C2 = Encrypt(P2 ^ C1)
	// ...
	// Cn = Encrypt(Pn ^ Cn-1)
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

	prev := make([]byte, blockSize)
	for i := range IV {
		prev[i] = IV[i]
	}

	processedInput := make([]byte, blockSize)

	for offset := 0; offset < len(input); offset += blockSize {
		for j := offset; j < offset+blockSize; j++ {
			processedInput[j-offset] = input[j] ^ prev[j-offset]
		}
		cipher.Encrypt(encrypted[offset:offset+blockSize], processedInput)
		prev = encrypted[offset : offset+blockSize]
	}
	return encrypted, nil
}

func DecryptAESCBC(input []byte, key []byte, IV []byte) ([]byte, error) {
	// Performs AES decryption in CBC mode
	// Here, the initial state is maintained by a random Initialization Vector (IV)
	// The flow is as follows: (Here, Pn represents the nth plaintext block, while Cn represents the nth ciphertext block)
	// P1 = Decrypt(C1) ^ IV
	// P2 = Decrypt(C2) ^ C1
	// ...
	// Pn = Decrypt(CN) ^ Cn-1
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
	prev := make([]byte, blockSize)
	for i := range IV {
		prev[i] = IV[i]
	}

	for offset := 0; offset < len(input); offset += blockSize {
		cipher.Decrypt(decrypted[offset:offset+blockSize], input[offset:offset+blockSize])
		for j := offset; j < offset+blockSize; j++ {
			decrypted[j] = decrypted[j] ^ prev[j-offset]
			prev[j-offset] = input[j]
		}
	}
	return decrypted, nil
}

func testAESCBC() {
	// Test function to ensure that our AES CBC encryption-decryption functions are valid
	input := []byte("This is a sample input consisting of more than required")
	key := []byte("ENCRYPTION KEYAB")
	input, paddingSize := addPadding(input, len(key), '\x00')
	IV := make([]byte, len(key))
	encrypted, _ := encryptAESCBC(input, key, IV)
	fmt.Println("Encrypted:", string(encrypted))
	decrypted, _ := DecryptAESCBC(encrypted, key, IV)
	fmt.Printf("Decrypted: '%s'\n", string(decrypted[:len(decrypted)-paddingSize]))
}

func main() {
	// AES CBC - Stateful encryption decryption with a symmetric key
	data, err := ioutil.ReadFile(path.Join("src/challenge10", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	key := []byte("YELLOW SUBMARINE")
	processed := decodeBase64(data)
	input, paddingSize := addPadding(processed, len(key), '\x00')
	IV := make([]byte, len(key))
	decrypted, _ := DecryptAESCBC(input, key, IV)
	fmt.Printf("Decrypted: '%s'\n", string(decrypted[:len(decrypted)-paddingSize]))
}

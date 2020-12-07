package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"

	"github.com/kuriringohankamehameha/crypto-stuff/cryptography"
)

var globalKey []byte
var unknownString []byte

func EncryptionOracleECB(input []byte, globalKey []byte) ([]byte, error) {
	key := globalKey
	blockSize := len(key)
	data := append(input, unknownString...)
	aesMode := &cryptography.AesMode{Mode: "ECB", IV: nil}
	data, _ = cryptography.AddPadding(data, blockSize, rune('\x00'))
	result, _ := cryptography.EncryptAES(data, globalKey, aesMode)
	return result, nil
}

func getECBEncryptionBlockSize(input []byte, globalKey []byte) int {
	repeatingSequence := make([]byte, 0)
	encrypted, _ := EncryptionOracleECB([]byte(string("")+string(input)), globalKey)
	prevLength := len(string(encrypted))
	for inputSize := 1; ; inputSize++ {
		repeatingSequence = append(repeatingSequence, []byte("A")...)
		encrypted, err := EncryptionOracleECB([]byte(string(repeatingSequence)+string(input)), globalKey)
		if err != nil {
			log.Panic(err)
		}
		if len(string(encrypted)) > prevLength {
			return len(encrypted) - prevLength
		}
	}
}

func DetectAESMode(encrypted []byte, keySize int, repeatingBlockSize int) (string, error) {
	// Detects if the encrypted input belongs to ECB / CBC
	repetitions := cryptography.GetRepetitions(encrypted, keySize)
	normalizedRepetitions := float64(repetitions) / float64(keySize)
	threshold := float64(repeatingBlockSize/2) / float64(keySize)
	if normalizedRepetitions > threshold {
		return "ECB", nil
	} else {
		return "CBC", nil
	}
}

func generateLookupTable(prefix []byte, blockSize int, offset int) map[string]byte {
	table := map[string]byte{}
	for i := 0; i < 255; i++ {
		input := append(prefix, byte(i))
		encrypted, err := EncryptionOracleECB(input, globalKey)
		if err != nil {
			log.Panic(err)
		}
		table[string(encrypted[offset:offset+blockSize])] = byte(i)
	}
	return table
}

func getBytefromTable(table map[string]byte, word []byte, offset int, blockSize int) byte {
	input := word
	encrypted, err := EncryptionOracleECB(input, globalKey)
	if err != nil {
		log.Panic(err)
	}
	_, ok := table[string(encrypted[offset:offset+blockSize])]
	if ok == true {
		result := table[string(encrypted[offset:offset+blockSize])]
		return result
	} else {
		log.Panicf("In table '%s' not present, %d", string(encrypted[offset:offset+blockSize]), len(string(encrypted[offset:offset+blockSize])))
	}
	return byte(0)
}

func getUnknownString(blockSize int) []byte {
	decrypted := make([]byte, 0)
	emptyEncrypted, _ := EncryptionOracleECB([]byte{}, globalKey)

	for len(decrypted) < len(emptyEncrypted) {
		offset := len(decrypted)
		for idx := blockSize - 1; idx >= 0; idx-- {
			// Start fetching the unknown bytes one by one
			repeatingBlock := bytes.Repeat([]byte("A"), idx)
			prefix := append(repeatingBlock, decrypted...)
			table := generateLookupTable(prefix, blockSize, offset)
			encrypted, _ := EncryptionOracleECB(repeatingBlock, globalKey)
			// Do a table lookup
			lookup, ok := table[string(encrypted[offset:offset+blockSize])]
			if ok == false {
				fmt.Printf("'%s' is Not there\n", encrypted[offset:offset+blockSize])
				return decrypted
			}
			decrypted = append(decrypted, lookup)
		}
	}
	return decrypted[:len(emptyEncrypted)]
}

func main() {
	textData := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	unknownString = cryptography.DecodeBase64(textData)
	globalKey = cryptography.GetRandomByteString(16)
	blockSize := getECBEncryptionBlockSize(cryptography.DecodeBase64(textData), globalKey)
	fmt.Println("Block Size:", blockSize)
	encrypted, _ := EncryptionOracleECB([]byte(strings.Repeat("A", 512)+string(cryptography.DecodeBase64(textData))), globalKey)
	mode, _ := DetectAESMode(encrypted, blockSize, 512)
	fmt.Println("Mode:", mode)
	word := getUnknownString(blockSize)
	decrypted := make([]byte, 0)
	for i := range word {
		if word[i] == byte(0) {
			break
		}
		decrypted = append(decrypted, word[i])
	}
	fmt.Printf("Decrypted Word = '%s'\n", string(decrypted))
	if len(cryptography.DecodeBase64(textData)) != len(decrypted) {
		fmt.Printf("Length: %d, but required = %d\n", len(decrypted), len(cryptography.DecodeBase64(textData)))
		log.Panic("Wrong length")
	}
	if string(cryptography.DecodeBase64(textData)) != string(decrypted) {
		log.Panic("Wrong answer")
	} else {
		log.Print("Correct Answer!")
	}
}

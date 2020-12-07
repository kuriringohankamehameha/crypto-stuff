package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/kuriringohankamehameha/crypto-stuff/cryptography"
)

func EncryptionOracle(input []byte, keySize int) ([]byte, error) {
	key := cryptography.GetRandomByteString(keySize)
	blockSize := len(key)
	aesModes := [2]cryptography.AesMode{{
		Mode: "ECB",
		IV:   nil,
	}, {
		Mode: "CBC",
		IV:   cryptography.GetRandomByteString(blockSize),
	}}

	prePaddingSize := cryptography.GetRandomInteger(5, 10)
	postPaddingSize := cryptography.GetRandomInteger(5, 10)
	prePadding := cryptography.GetRandomByteString(prePaddingSize)
	postPadding := cryptography.GetRandomByteString(postPaddingSize)
	paddedInput, _ := cryptography.PKCSPad([]byte(string(prePadding)+string(input)+string(postPadding)), blockSize)
	choice := cryptography.GetRandomInteger(0, 1)
	aesMode := &aesModes[choice%len(aesModes)]
	fmt.Println("Encrypting under mode:", aesMode.Mode)
	encrypted, err := cryptography.EncryptAES(paddedInput, key, aesMode)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func DetectAESMode(encrypted []byte, keySize int, repeatingBlockSize int) (string, error) {
	// Detects if the encrypted input belongs to ECB / CBC
	// fmt.Printf("Encrypted Input: '%s'\n", encrypted)
	repetitions := cryptography.GetRepetitions(encrypted, keySize)
	normalizedRepetitions := float64(repetitions) / float64(keySize)
	threshold := float64(repeatingBlockSize/2) / float64(keySize)
	if normalizedRepetitions > threshold {
		return "ECB", nil
	} else {
		return "CBC", nil
	}
}

func main() {
	data := []byte("This is a sample string which will be encrypted!")
	repeatingPlaintext := strings.Repeat("0", 512) // Generate a large enough sequence of repeating plaintext characters
	preprocessedData := []byte(string(repeatingPlaintext) + string(data))
	encrypted, err := EncryptionOracle(preprocessedData, 16)
	if err != nil {
		log.Panic(err)
	}
	// fmt.Println(string(encrypted))
	encryptionMode, _ := DetectAESMode(encrypted, 16, len(repeatingPlaintext))
	fmt.Println("Encryption Mode:", encryptionMode)
}

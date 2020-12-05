package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"github.com/kuriringohankamehameha/crypto-stuff/cryptography"
)


func testAESCBC() {
	// Test function to ensure that our AES CBC encryption-decryption functions are valid
	input := []byte("This is a sample input consisting of more than required")
	key := []byte("ENCRYPTION KEYAB")
	aesMode := &cryptography.AesMode{
		Mode: "CBC",
		IV: make([]byte, len(key)),
	}
	input, paddingSize := cryptography.AddPadding(input, len(key), '\x00')
	encrypted, _ := cryptography.EncryptAES(input, key, aesMode)
	fmt.Println("Encrypted:", string(encrypted))
	decrypted, _ := cryptography.DecryptAES(encrypted, key, aesMode)
	fmt.Printf("Decrypted: '%s'\n", string(decrypted[:len(decrypted)-paddingSize]))
}

func main() {
	// AES CBC - Stateful encryption decryption with a symmetric key
	data, err := ioutil.ReadFile(path.Join("src/challenge10", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	key := []byte("YELLOW SUBMARINE")
	aesMode := &cryptography.AesMode{
		Mode: "CBC",
		IV: make([]byte, len(key)),
	}
	processed := cryptography.DecodeBase64(data)
	input, paddingSize := cryptography.AddPadding(processed, len(key), '\x00')
	decrypted, _ := cryptography.DecryptAES(input, key, aesMode)
	fmt.Printf("Decrypted: '%s'\n", string(decrypted[:len(decrypted)-paddingSize]))
}

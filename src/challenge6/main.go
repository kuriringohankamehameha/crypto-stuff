package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"

	"github.com/kuriringohankamehameha/crypto-stuff/cryptography"
)

func main() {
	// data is base64'd after being encrypted with repeating-key XOR.
	data, err := ioutil.ReadFile(path.Join("src/challenge6", "input.txt"))
	if err != nil {
		log.Panic("Error while opening file:", err)
	}
	processed := cryptography.DecodeBase64(data)
	distance := cryptography.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if distance != 37 {
		log.Panic("Incorrect hamming distance")
	}
	result := cryptography.DecryptVignere(processed, 40)
	fmt.Println(string(result))
}

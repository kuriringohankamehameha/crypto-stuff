package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
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

func main() {
	inputbyteString := []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	decodedbyteString, n := hextoBase64(inputbyteString)

	fmt.Println("Input Hex String:", string(inputbyteString))
	fmt.Println("Encoded Base64 String:", string(decodedbyteString[:n]))
}

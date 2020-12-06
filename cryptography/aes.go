package cryptography

import (
	"crypto/aes"
	"errors"
)

type AesMode struct {
	Mode string
	IV   []byte
}

func EncryptAES(input []byte, key []byte, aesMode *AesMode) ([]byte, error) {
	if aesMode.Mode == "ECB" {
		return encryptAESECB(input, key)
	} else if aesMode.Mode == "CBC" {
		return encryptAESCBC(input, key, aesMode.IV)
	} else {
		err := errors.New("Unknown AES Encryption Mode")
		return nil, err
	}
}

func DecryptAES(input []byte, key []byte, aesMode *AesMode) ([]byte, error) {
	if aesMode.Mode == "ECB" {
		return decryptAESECB(input, key)
	} else if aesMode.Mode == "CBC" {
		return decryptAESCBC(input, key, aesMode.IV)
	} else {
		err := errors.New("Unknown AES Decryption Mode")
		return nil, err
	}
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

	if IV == nil {
		err = errors.New("Initialization Vector for CBC mode must not be nil")
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

func decryptAESECB(input []byte, key []byte) ([]byte, error) {
	// Performs AES decryption in ECB mode
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

func decryptAESCBC(input []byte, key []byte, IV []byte) ([]byte, error) {
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

func GetRepetitions(cipherText []byte, keySize int) int {
	// Finds the number of ciphertext repetitions
	// and tries to correlate the maximum repeating word to ECB encryption
	cipherTexts := make([][]byte, 0)

	cipherText, _ = AddPadding(cipherText, keySize, rune('\x00'))
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

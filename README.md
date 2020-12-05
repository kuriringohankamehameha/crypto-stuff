# Cryptography Experiments

This repository attempts to document my learning experiences with cryptography, via the website https://cryptopals.com/

Also serves as a good way for me to pick up Golang, so I'm doing it in Go!

## Challenges

Attempts can be found at `src/challengeN/main.go`

Current Progress: Set 1 challenges are complete

Disclaimer: This code is not following the best practices, and several optimizations are possible. The repository is only for educational purposes, since I haven't found too many implementations in Go.

### Challenge 4

This involves finding the plaintext which has been single character XOR encrypted. Several approaches are possible, but we'll be using a frequency based detection. We first get the frequency distribution prior for the english alphabet. Also note that the space character (' ') is crucial in this distribution. We'll be assigning this to the highest probability (2x the probability of the next highest character - 'e')

After we build our distribution table, we can simply do a brute force among the ascii characters (0-255) and only select the key and the word with the highest score globally.

### Challenge 5

This is straightforward encryption of a repeating key, using XOR.

### Challenge 6

This challenge involves multiple steps in order to brute force attack the Vignere Encryption. Since the encryption uses a cyclic XOR function, it is possible to detect repeating patterns in the ciphertext through estimating the key size.

If the key size is known, we can simply perform a frequency analysis of the ciphertext, which can give the plaintext with a high probability.

To estimate the key size, we use another similarity measurement to check if there are any repeating patterns in the ciphertext. Since a block of text `CIPHERTEXT[a:b] ^ key` can give similar frequency distributions, we try a brute-force on the key size, by finding the maximum normalized hamming distance between the ciphertext.

The crucial aspect is that this encryption-decryption technique is block based, so once we have the key length, we divide the input into key sized blocks. Now the key bit for each block can be found by the single bit repeating XOR function. Simply add all the key bits for all the XOR blocks, and you get your key!

### Challenges 7 and 8

These are straightforward if you aren't trying to implement AES from scratch.

Since I'm not trying to do the hard way for now, the standard library has the respective helpers at `crypto/aes` for encryption and decryption.

In challenge 7, Simply divide the input into blocks of text, and encrypt/decrypt them. The only tricky part is realizing that the input needs to be padded *before* encryption / decryption takes place.

Challenge 8 gives us a file for us to predict which line of text has been ECB encrypted. Since this encryption code is stateless, we try to look at the maximum number of ciphertext repetitions, since that will directly give us the number of plaintext repetitions. This correlation and one-one mapping is what makes ECB insecure, since the mapping is constant. In fact, it is so insecure that the Go standard library intentionally left it out in the crypto library!

**********************
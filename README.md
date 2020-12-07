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

### Challenge 9

I've already implemented the padding before for Challenge 7, so this was pretty much done already. The only other change was to add a padding character (previously I just assumed it to be '\x00')

### Challenge 10

This one was a good challenge involved in implementing AES Encryption and Decryption in CBC mode.

Here, we have an additional *Initialization Vector* (IV) which is used for maintaining the state of the encryption/decryption, in addition to the symmetric key.

This solves one of the major problems of ECB mode encryption/decryption, and makes it much harder to perform brute force attacks.

For encryption, the process can be roughly summarized as follows:


* Encryption in AES-CBC Mode:
```
    Here, Pn represents the nth plaintext block, while Cn represents the nth ciphertext block - IV = Initialization Vector)
    P1 = Decrypt(C1) ^ IV
	P2 = Decrypt(C2) ^ C1
	...
	Pn = Decrypt(CN) ^ Cn-1
```

* Decryption in AES-CBC Mode:
```
    Here, Pn represents the nth plaintext block, while Cn represents the nth ciphertext block - IV = Initialization Vector)
	C1 = Encrypt(P1 ^ IV)
	C2 = Encrypt(P2 ^ C1)
	...
	Cn = Encrypt(Pn ^ Cn-1)
```

Here, the `Encrypt()` and `Decrypt()` functions can be optained via the AES cipher.

### Challenge 11

This is a very nice challenge which needs us to determine the mode of AES encryption (ECB / CBC). Here, we construct an oracle which encrypts the input randomly via either ECB / CBC.

```bash
encrypted = oracle(input) # Can encrypt in either ECB / CBC modes
```

We need to find the mode of encryption which the oracle uses every time, given that we have no prior knowledge about the key / IV.

Here, trying to find the repetitions via a fixed input will *not* work, since the input is randomly padded with bytes. Therefore, if the input is small, we have no way of detecting if ECB is even used!

The most natural approach would be to try to construct intentionally repetitions on the input itself! If our input size is sufficiently large and containts multiple repeated plaintext blocks, the random padding could still not be able to contain ECB.

So I assume that we can extend the input size arbitrarily, and prepend a repeating sequence of "0" of length 512 bytes. Now, to this processed input (`000...00 + input`), we find the number of repeating ciphertext blocks, which will then give ECB if the repetitions are beyond a threshold (assume `min(inputSize/blockSize)`). Otherwise, it is in CBC mode.

### Challenge 12

I took a long time to solve this challenge, and I blame the question description for this. It seems that the new Oracle *shouldn't* use the random 5-10 bytes padding at the beginning and at the end, unlike the last challenge.

So the approach is to first get the block size of the cipher, which can be found out via cummulating queries to the Oracle. Keep feeding in strings from "A", "AA", etc until we detect that the output length has increased. Therefore, `blockSize = len(newOutput) - len(prevOutput)`.

Once we get the block size and verify that the Oracle uses `ECB` mode, we can try an attack which uses block based lookups to find the encryption match.

Since ECB does the encryption in blocks, if we get the block size, we can get the decrypted bytes one by one. How? By feeding special sequences to the Oracle.

We use a sequence block of the form `AAA...D1D2S1`, which can be understood as `[repeatingSequence, DecryptedSequence, SecretByte]`. We use a lookup table to construct a mapping from every encrypted string wrt this input sequence for every byte.

We can then check this lookup table for the same prefix, without the trailing byte. Since the oracle will supply the unknown byte, all we need to do is to match that for every single block!

However, if you use the same Oracle from the previous challenge, this won't generate consistent lookups, since the same encryption sequence will only map to a random padding byte. Random padding + ECB can't be broken using the lookup method.

Roughly, the problem can be formulated as follows:

```python
def decrypt(offset, blockSize, prefix, repeatingSequence):
	cipherText = oracle("")
	decrypted = ""
	while len(decrypted) < len(ciphterText)
		for i in range(blockSize):
			seq = repeatingSequence[:-i] + prefix
			table = constructLookup(seq)
			encrypted = oracle(repeatingSequence[:-i])
			secretByte = lookup(table, encrypted[:blockSize])
			decrypted += secretByte
	return decrypted
```

**********************
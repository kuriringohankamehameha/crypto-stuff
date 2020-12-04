# Cryptography Experiments

This repository attempts to document my learning experiences with cryptography, via the website https://cryptopals.com/

Also serves as a good way for me to pick up Golang, so I'm doing it in Go!

## Challenges

Attempts can be found at `src/challengeN/main.go`

### Challenges 7 and 8

These are straightforward if you aren't trying to implement AES-ECB from scratch.

Since I'm not trying to do the hard way for now, the standard library has the respective helpers at `crypto/aes` for encryption and decryption.

In challenge 7, Simply divide the input into blocks of text, and encrypt/decrypt them. The only tricky part is realizing that the input needs to be padded *before* encryption / decryption takes place.

Challenge 8 gives us a file for us to predict which line of text has been ECB encrypted. Since this encryption code is stateless, we try to look at the maximum number of ciphertext repetitions, since that will directly give us the number of plaintext repetitions. This correlation and one-one mapping is what makes AES-ECB insecure. In fact, it is so insecure that the Go standard library intentionally left it out in the crypto library!

## Look at other writeups and approaches

Although I've completed some of the challenges, I need to look at how the others have attempted the harder ones (such as challenge 6) since my implementation is definitely not optimized

* http://blog.joshuahaddad.com/cryptopals-challenges-6/
* https://medium.com/@__cpg/cryptopals-1-6-cracking-vigen%C3%A8re-cipher-9c52e098443d (Could be an interesting read - didn't read it myself)

* AES Related Resources - 
* https://www.samiam.org/galois.html
* https://www.samiam.org/s-box.html
* https://www.samiam.org/key-schedule.html
* https://crypto.stackexchange.com/questions/20/what-are-the-practical-differences-between-256-bit-192-bit-and-128-bit-aes-enc/1527#1527
* https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
* https://crypto.stackexchange.com/questions/31459/aes-inverse-key-schedule
* https://www.youtube.com/watch?v=MbFcV1SK6U8
* https://cedricvanrompay.gitlab.io/cryptopals/challenges/01-to-08.html
* https://github.com/asggo/cryptanalysis

**********************
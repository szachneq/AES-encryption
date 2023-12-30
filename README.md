# AES cipher - software implementation, ECB and CBC ciphering modes

## Authors
 - Aleksandra Głogowska
 - Jan Szachno

## Description of the algorithm

128 bit symmetric block cipher that uses the same key for encryption and decryption.

TODO - elaborate

## Scratchpad notes

3 sizes of key: 128, 192 and 256

The major difference between ECB and CBC is that ECB encrypts each block independently, whereas CBC encrypts each block with the previous block. CBC is therefore considered more secure and resistant to pattern recognition attacks than ECB

the message is split up into 128 bit blocks
4 rows and 4 columns
each entry is 2 hex characters (1 byte)
16 bytes = 128 bits
this is always the same 128 bit blocks, the key size may differ
The size of encrypted data remains the same, meaning that 128 bits of plaintext yield 128 bits of ciphertext.

later, we create a certain number of round keys
they are created from the cipher key
they can be considered as a bunch of mini keys, derived from original one
they are each 128 bits
we will do a for loop over the message blocks of original data
algorithm:
 - for each block of 16 bytes of data
 - combine it with one of the round keys by doing a bitwise XOR between the bytes of the block and the bytes of the key
 - do some math (byte substitution) on that block input combined with the key to further obscure. It converts every byte into a different value. AES will define a table of 256 values. Each value of the block will be replaced with a different one, and cannot be mapped to itself. It is implemented as lookup table.
 - shift the rows to the left by an incrementing number of bytes (0, 1, 2, ....)
 - mix the columns (some matrix multiplication involved)
 - repeat a couple of times depending on the key size (128 - 10 times, 192 - 12 times, 256 - 14 times)
 - in the last iteration we skip column mixing

decryption is simply done in reverse



When encrypting a message with AES in a mode of operation that uses an IV (such as CBC mode), the IV is combined with the first block of plaintext before encryption. This modified block is then encrypted using the AES algorithm. For subsequent blocks, the previous ciphertext block is XORed with the current plaintext block before encryption.

The Initialization Vector (IV) is a crucial component in the operation of block ciphers, including the Advanced Encryption Standard (AES). The purpose of the IV is to ensure that the same plaintext encrypted with the same key will produce different ciphertexts each time it is encrypted. This property is important for security, as it helps prevent patterns from emerging in the ciphertext, even when encrypting the same message multiple times.

In AES, the IV is an additional input used during the encryption process. It is a block of data that is the same size as the block size of the cipher. For AES, which has a block size of 128 bits (16 bytes), the IV is also 128 bits.

## Resources
 - [Advanced Encryption Standard - Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
 - [Block cipher mode of operation - Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))
 - [How AES Encryption Works - YouTube](https://www.youtube.com/watch?v=A8poO23ujxA)
 - [AES Explained - Youtube](https://www.youtube.com/watch?v=O4xNJsjtN6E)
 - [AES Encryption and Decryption - YouTube](https://www.youtube.com/watch?v=4KiwoeDJFiA)
 - [Advanced Encryption Standard (AES)](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/)
 - [A Stick Figure Guide to the Advanced Encryption Standard (AES)](https://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html)
 - [Implementing AES](https://blog.nindalf.com/posts/implementing-aes/)
 - [tiny-AES-c - GitHub](https://github.com/kokke/tiny-AES-c/tree/master)
 - [PyCryptodome](https://www.pycryptodome.org/)

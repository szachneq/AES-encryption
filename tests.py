#!/usr/bin/env python
import unittest
from Crypto.Cipher import AES
from common import list_to_hex_str, list_to_str
from aes_ecb_encrypt import aes_ecb_encrypt
from aes_cbc_encrypt import aes_cbc_encrypt
from aes_ecb_decrypt import aes_ecb_decrypt
from aes_cbc_decrypt import aes_cbc_decrypt

class TestEncryptECB(unittest.TestCase):
    def test_ecb_encrypt_128_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnop'
        msg_str = 'abcdefghijklmnop'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 128 bit key should be equal")

    def test_ecb_encrypt_128_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv'
        msg_str = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 128 bit key should be equal")

    def test_ecb_encrypt_192_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwx'
        msg_str = 'abcdefghijklmnop'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 192 bit key should be equal")

    def test_ecb_encrypt_192_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn'
        msg_str = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 192 bit key should be equal")

    def test_ecb_encrypt_256_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwxyzabcdef'
        msg_str = 'abcdefghijklmnop'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 256 bit key should be equal")

    def test_ecb_encrypt_256_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,'
        msg_str = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_ecb_encrypt(msg_str, key_str)

        self.assertEqual(res, reference, "Results for ECB encryption with 256 bit key should be equal")

class TestEncryptCBC(unittest.TestCase):
    def test_cbc_encrypt_128_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnop'
        msg_str = 'abcdefghijklmnop'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 128 bit key should be equal")

    def test_cbc_encrypt_128_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv'
        msg_str = "My special message you won't see"
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 128 bit key should be equal")

    def test_cbc_encrypt_192_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwx'
        msg_str = 'abcdefghijklmnop'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 192 bit key should be equal")

    def test_cbc_encrypt_192_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn'
        msg_str = "My special message you won't see"
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 192 bit key should be equal")

    def test_cbc_encrypt_256_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwxyzabcdef'
        msg_str = 'abcdefghijklmnop'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 256 bit key should be equal")

    def test_cbc_encrypt_256_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,'
        msg_str = "My special message you won't see"
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 256 bit key should be equal")

    def test_cbc_encrypt_256_two(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwxyzabcdef'
        msg_str = "My special message you won't see"
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        msg_bytes = msg_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.encrypt(msg_bytes)
        reference = list_to_hex_str(reference)
        # compute our result
        res = aes_cbc_encrypt(msg_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC encryption with 256 bit key should be equal")

class TestDecryptECB(unittest.TestCase):
    def test_ecb_decrypt_128_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnop'
        crypto_str = 'a91329af99a78d02aec17c507757aaef'
        expected_msg = "abcdefghijklmnop"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 128 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 128 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 128 bit key should be equal")

    def test_ecb_decrypt_128_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv'
        crypto_str = '3864fee78b265431092f3947a686d5b2277302a68c41ea66f1dee33bcf3a09fa'
        expected_msg = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 128 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 128 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 128 bit key should be equal")

    def test_ecb_decrypt_192_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwx'
        crypto_str = '658ef28763378cef9f0677c63c91c330'
        expected_msg = "abcdefghijklmnop"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 192 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 192 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 192 bit key should be equal")

    def test_ecb_decrypt_192_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn'
        crypto_str = '1c25a336a846dd44d8d31323233ce59fc92d70fcaec52753e58a990b8cc863d4'
        expected_msg = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 192 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 192 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 192 bit key should be equal")

    def test_ecb_decrypt_256_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwxyzabcdef'
        crypto_str = 'c806dee9da8edc7c742961e5e61a08de'
        expected_msg = "abcdefghijklmnop"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 256 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 256 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 256 bit key should be equal")

    def test_ecb_decrypt_256_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,'
        crypto_str = '0324ab978af2f9a50a3517a5b13d3081fed95cbbae5e9e84e9962a949f0969b8'
        expected_msg = "My special message you won't see"
        key_bytes = key_str.encode('utf-8')
        # convery every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))
        
        # compute reference
        c = AES.new(key_bytes, AES.MODE_ECB)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_ecb_decrypt(crypto_str, key_str)

        self.assertEqual(res, expected_msg, "Results for ECB decryption with 256 bit key should be equal")
        self.assertEqual(reference, expected_msg, "Results for ECB decryption with 256 bit key should be equal")
        self.assertEqual(res, reference, "Results for ECB decryption with 256 bit key should be equal")

class TestDecryptCBC(unittest.TestCase):
    def test_cbc_decrypt_128_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnop'
        crypto_str = '658ef28763378cef9f0677c63c91c330'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 128 bit key should be equal")

    def test_cbc_decrypt_128_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv'
        crypto_str = '2fa65a6e9702a8ff332a063cd4e66f0650f66056f8d662ccec446310b4cfe6e3'
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 128 bit key should be equal")

    def test_cbc_decrypt_192_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwx'
        crypto_str = '3e438afaea40bcdf33007c272db104cc'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 192 bit key should be equal")

    def test_cbc_decrypt_192_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn'
        crypto_str = '92e507fcde55babacacbd8dd19ad2b460dc1cccdf3ae1259098acae2332e9816'
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 192 bit key should be equal")

    def test_cbc_decrypt_256_one(self):
        # prepare test case input data
        key_str = 'abcdefghijklmnopqrstuvwxyzabcdef'
        crypto_str = '88b596a78c3f98d70ab28e3adf858b5d'
        iv_str = 'ponmlkjihgfedcba'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 256 bit key should be equal")

    def test_cbc_decrypt_256_two(self):
        # prepare test case input data
        key_str = '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,'
        crypto_str = 'f65cc9a9da45a0a9114cdd661b2302ab3acda89e2691e15441e7b59927b43bb4'
        iv_str = 'qwertyuiopasdfgh'
        key_bytes = key_str.encode('utf-8')
        iv_bytes = iv_str.encode('utf-8')
        # convert every 2 letters into a hex number
        crypto_bytes = bytes(int(crypto_str[i:i+2], 16) for i in range(0, len(crypto_str), 2))

        # compute reference
        c = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        reference = c.decrypt(crypto_bytes)
        reference = list_to_str(reference)
        # compute our result
        res = aes_cbc_decrypt(crypto_str, key_str, iv_str)

        self.assertEqual(res, reference, "Results for CBC decryption with 256 bit key should be equal")

if __name__ == '__main__':
    unittest.main()

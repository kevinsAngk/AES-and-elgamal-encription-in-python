# encrypt.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import sympy
import random

# AES Encryption
def encrypt_aes(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return ciphertext, iv

# elgamal_encryption
def elgamal_encrypt(p, g, h, encrypted_message):
    ciphertexts = []

    for m in encrypted_message:
        k = random.randint(1, p - 2)
        y = pow(g, k, p)
        s = pow(h, k, p)
        c1 = pow(g, k, p)
        c2 = (m * s) % p
        ciphertexts.append((c1, c2))

    return ciphertexts

if __name__ == "__main__":
    # Key generation for AES
    key = get_random_bytes(16)  # 128-bit key for AES (256/8)
    iv = get_random_bytes(16)   # Initialization Vector
    message = "Hello, AES and ElGamal encryption!"

    # ElGamal parameters
    p = sympy.randprime(2**127, 2**128)
    g = sympy.primitive_root(p)
    x = random.randint(1, p - 2)
    h = pow(g, x, p)

    # AESEncryption
    AES_ciphertext, iv_used = encrypt_aes(message, key, iv)

    # Encrypt AES key using ElGamal
    aes_key_encrypt = elgamal_encrypt(p, g, h, key)

    print("Encrypted Message:", AES_ciphertext)
    print("Encrypted AES Key:", aes_key_encrypt)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sympy
import random

# Key generation for AES
key = get_random_bytes(16)  # 128-bit key for AES(256/8)
iv = get_random_bytes(16)   # Initialization Vector
message = "Hello, AES and elgramal encryption and decryption TeSt for thesis!"

# ElGamal parameters
p = sympy.randprime(2**127, 2**128)
g = sympy.primitive_root(p)
x = random.randint(1, p - 2)
h = pow(g, x, p)

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
	
# AES Decryption
def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')
	
# elgamal_decryption
def elgamal_decrypt(p, x, ciphertexts):
    decrypted_values = []
    
    for c1, c2 in ciphertexts:
        s = pow(c1, x, p)
        s_inverse = pow(s, -1, p)
        decrypted_m = (c2 * s_inverse) % p
        decrypted_values.append(decrypted_m)
    
    decrypted_message = bytes(decrypted_values)
    return decrypted_message
	
# AESEncryption
AES_ciphertext, iv_used = encrypt_aes(message, key, iv)

# Encrypt AES encrypted message using ElGamal
aes_key_encrypt = elgamal_encrypt(p, g, h, key)

# Decrypt ElGamal key
decrypted_key = elgamal_decrypt(p, x, aes_key_encrypt)

# Decryption
decrypted_message = decrypt_aes(AES_ciphertext, decrypted_key, iv_used)

print("Original Message:", message)
print("Encrypted Message:", AES_ciphertext)
print("Encrypted key:", aes_key_encrypt)
print("Decrypted Message:", decrypted_message)

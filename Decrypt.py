# decrypt.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sympy

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

if __name__ == "__main__":
    # Use the ciphertexts and keys obtained from the encryption process
    AES_ciphertext = b'...'  # Replace with actual ciphertext
    iv_used = b'...'         # Replace with actual IV
    aes_key_encrypt = [(c1, c2) for c1, c2 in [(1, 2), (3, 4)]]  # Replace with actual ElGamal ciphertexts

    # Decryption
    decrypted_key = elgamal_decrypt(p, x, aes_key_encrypt)
    decrypted_message = decrypt_aes(AES_ciphertext, decrypted_key, iv_used)

    print("Decrypted Message:", decrypted_message)

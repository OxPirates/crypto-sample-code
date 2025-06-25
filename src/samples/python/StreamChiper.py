from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

# Key and nonce generation
key = os.urandom(32)  # 256-bit key
nonce = os.urandom(12)  # Recommended 12 bytes for GCM

# Data to encrypt
plaintext = b"Secret message"

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag

print(f"AES Ciphertext: {ciphertext.hex()}")

# Decrypt
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()

print(f"AES Decrypted: {decrypted.decode()}")


key = os.urandom(32)  # 256-bit key
nonce = os.urandom(16)  # 128-bit nonce for ChaCha20

plaintext = b"Secret message"

cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext)

print(f"ChaCha20 Ciphertext: {ciphertext.hex()}")

# Decrypt (same key and nonce)
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
decryptor = cipher.decryptor()
decrypted = decryptor.update(ciphertext)

print(f"ChaCha20 Decrypted: {decrypted.decode()}")
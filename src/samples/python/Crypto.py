# Requires: pip install pysha3 blake3

import hashlib  # for SHA3
import blake3

data = b"Hello, post-quantum world!"

# SHA3-512
sha3_512 = hashlib.sha3_512()
sha3_512.update(data)
digest_sha3 = sha3_512.digest()
print("SHA3-512:", digest_sha3.hex())

# BLAKE3 (default output length 32 bytes, can extend)
digest_blake3 = blake3.blake3(data).digest()
print("BLAKE3 (256-bit):", digest_blake3.hex())

# BLAKE3 extended output (e.g. 64 bytes)
digest_blake3_long = blake3.blake3(data).digest(length=64)
print("BLAKE3 (512-bit):", digest_blake3_long.hex())


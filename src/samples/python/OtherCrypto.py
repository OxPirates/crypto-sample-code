from secrets import compare_digest
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt

# Alice generates a (public, secret) key pair
public_key, secret_key = generate_keypair()

# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = decrypt(secret_key, ciphertext)

# Compare the original and recovered secrets in constant time
assert compare_digest(plaintext_original, plaintext_recovered)


from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

# Generate signing key pair
public_key, secret_key = generate_keypair()

message = b"Post-quantum signature test"

# Sign the message with secret key
signature = sign(message, secret_key)

# Verify the signature with the public key
is_valid = verify(signature, message, public_key)

print("Signature valid:", is_valid)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os

# Generate a key from a password
def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_length, count=1000000)

# Simulate ABE setup
def setup():
    master_key = get_random_bytes(32)
    return master_key

# Simulate ABE encryption
def encrypt(message: str, policy: str, master_key: bytes):
    salt = get_random_bytes(16)
    key = derive_key(policy, master_key + salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, tag, cipher.nonce, salt

# Simulate ABE key generation for specific attributes
def keygen(master_key: bytes, attributes: list):
    return master_key, " and ".join(attributes)

# Simulate ABE decryption
def decrypt(ciphertext: bytes, tag: bytes, nonce: bytes, salt: bytes, policy: str, master_key: bytes):
    key = derive_key(policy, master_key + salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except ValueError:
        raise ValueError("Decryption failed due to attribute mismatch or data corruption")

# Example usage
master_key = setup()
attributes = ["attr1", "attr3"]
policy = "attr1 and attr2"
message = "Hello, Attribute-Based Encryption!"

# Generate secret key
_, policy_str = keygen(master_key, attributes)

# Encrypt the message
ciphertext, tag, nonce, salt = encrypt(message, policy_str, master_key)
print(ciphertext)

# Decrypt the message
try:
    decrypted_message = decrypt(ciphertext, tag, nonce, salt, policy_str, master_key)
    print("Decrypted Message:", decrypted_message)
except ValueError as e:
    print(str(e))
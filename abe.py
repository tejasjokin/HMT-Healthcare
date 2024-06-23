from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import base64
from dotenv import load_dotenv

os.environ['ABE_MASTER_KEY'] = 'testMasterKey'
os.environ['ABE_PUBLIC_KEY'] = 'testPublicKey'

# Generate a key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Simulate ABE setup
def setup():
    load_dotenv()
    master_key = os.getenv('ABE_MASTER_KEY')
    public_key = os.getenv('ABE_PUBLIC_KEY')
    return master_key, public_key

# Get Encryption key
def genEncryptionKey(attributes: list):
    master_key, _ = setup()
    policy = ",".join(attributes)
    key = derive_key(policy, master_key.encode())
    return key

def genDecryptionKey(attributes: list):
    master_key, _ = setup()
    key = derive_key(",".join(attributes), master_key.encode())
    return key

# Simulate ABE encryption
def encrypt(public_key: bytes, message: str, policy: str, master_key: bytes):
    key = derive_key(policy, master_key)
    cipher = Cipher(algorithms.AES(key), modes.GCM(public_key), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, encryptor.tag

# Simulate ABE key generation for specific attributes
def keygen(master_key: bytes, attributes: list):
    return derive_key(" and ".join(attributes), master_key)

# Simulate ABE decryption
def decrypt(public_key: bytes, secret_key: bytes, ciphertext: bytes, tag: bytes, salt: bytes, policy: str):
    key = derive_key(policy, salt)
    if key != secret_key:
        raise ValueError("Decryption failed due to attribute mismatch")
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(public_key, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Example usage
master_key, public_key = setup()
policy = "attr1 and attr2"
message = "Hello, Attribute-Based Encryption!"
ciphertext, tag = encrypt(public_key.encode(), message, policy, master_key.encode())
print("Encrypted Message: "+base64.b64encode(ciphertext).decode())

attributes = ["attr1", "attr2"]
secret_key = keygen(master_key.encode(), attributes)


try:
    decrypted_message = decrypt(public_key.encode(), secret_key, ciphertext, tag, master_key.encode(), policy)
    print("Decrypted Message:", decrypted_message)
except ValueError as e:
    print(str(e))
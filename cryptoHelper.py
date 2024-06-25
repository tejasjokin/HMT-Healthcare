from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_key_pair():
    """
    Generate an RSA key pair and return the public and private keys in PEM format.
    
    Returns:
        tuple: (public_key_ssh, public_key_pem, private_key_pem)
            - public_key_ssh (str): Public key in OpenSSH format.
            - public_key_pem (str): Public key in PEM format.
            - private_key_pem (str): Private key in PEM format.
    """
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent
        key_size=4096,  # Key size in bits
        backend=default_backend()
    )

    # Get the public key in OpenSSH format for storage or transmission
    public_key_ssh = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')

    # Get the public key in PEM format
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Serialize the private key to PEM format for storage (not encrypted)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return public_key_ssh, public_key_pem, private_key_pem

# Example function for signing data
def sign_data(private_key_pem, data):
    try:
        # Load the private key from PEM format
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        # Convert data to JSON string and ensure it's encoded as bytes
        data_bytes = json.dumps(data).encode('utf-8')

        # Hash the data
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(data_bytes)
        digest = hasher.finalize()

        # Sign the hash using PKCS#1 v1.5 padding
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Encode signature to base64 for readability
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        return signature_b64, digest

    except Exception as e:
        print(f"An error occurred during signing: {e}")
        return None
    
# Example function for verifying signature
def verify_signature(public_key_pem, data, signature_b64):
    try:
        # Load the public key from PEM format
        public_key = load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Convert data to JSON string and ensure it's encoded as bytes
        data_bytes = json.dumps(data).encode('utf-8')

        # Hash the data
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(data_bytes)
        digest = hasher.finalize()

        # Decode the base64 signature
        signature = base64.b64decode(signature_b64)

        # Verify the signature
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature verified successfully.")
        return True

    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Example function for encrypting data
def encrypt_data(public_key_pem, data):
    try:
        # Load the public key from PEM format
        public_key = load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )

        # Convert data to JSON string and ensure it's encoded as bytes
        data_bytes = json.dumps(data).encode('utf-8')

        # Maximum length check for RSA encryption
        max_length = public_key.key_size // 8 - 2 * hashes.SHA256().digest_size - 2

        if len(data_bytes) > max_length:
            raise ValueError(f"Data length ({len(data_bytes)}) exceeds maximum allowed ({max_length}) for RSA encryption.")

        # Encrypt the data using RSA-OAEP padding
        encrypted_chunks = []
        for i in range(0, len(data_bytes), max_length):
            chunk = data_bytes[i:i + max_length]
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))

        return encrypted_chunks

    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None

def decrypt_data(private_key_pem, encrypted_chunks):
    try:
        # Load the private key from PEM format
        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )

        # Initialize a list to hold decrypted chunks
        decrypted_chunks = []

        # Decode each encrypted chunk, decrypt it, and accumulate decrypted chunks
        for encrypted_chunk_b64 in encrypted_chunks:
            encrypted_chunk = base64.b64decode(encrypted_chunk_b64)
            decrypted_chunk = private_key.decrypt(
                encrypted_chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)

        # Concatenate decrypted chunks and decode JSON
        decrypted_data = json.loads(b"".join(decrypted_chunks).decode('utf-8'))
        return decrypted_data

    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None


# Generate RSA key pair (if not already generated)
#public_key_ssh, public_key_pem, private_key_pem = generate_rsa_key_pair()

private_key_pem = """
-----BEGIN PRIVATE KEY-----
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
rzwAvRF7Khe5yXywHPOt662bUY13Aw==
-----END PRIVATE KEY-----
"""

public_key_pem=""" 
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8krzFriWYDBGXvWlEzK0
T+Pm8s/CkA7axtaFNXhL+VcCd+ROVeSsUuw6h38zsjnOZplnk28EQYl9V8yRoFDm
OsLcFY9Auc7TcABP9AphNqLYfG5fpeSmsRvh+7lxVq6/wiXpxSNkNZbN6Bf9KQFr
uEGbqy04H5YiMP8Bi6m74p+x3J/ggEYDAVrQn7ACHcfCAJXEtBVSoPgVi6LvUz0r
GLPBvlqjPNjJeRzT2K1vfobggwwoHTvf/4My/b55loK//C1w4KFT1sQVoqK8y73V
XkT8s4EiNmx3qzS+Eum3vRVNBM+Z6u48N6qsqoWHz0wr/uqOJfOh6460+GbXX+T1
uw9UiuIzjdpGor+KLrVYr0eHJfbMvebQ6aHW8PxgxofXcZbAxpDMP6L57zXJa93m
Kom03PsKg5MVj0+ugwirZPk30MbUtdxAC6bFS/j1ELtD9M4oALyWu1CF6OF9G/qF
K7ENEqCe120cq9TPKBvWjmT32RYdhubfItIUF0ldcMgO02vWZjwzIb/HIEUfLln3
/l7qGd/Tua0q60mIpL7KimxsLwiRIDyjshSknaURYDOTfjVNaVDVZNyAUqJCT1c9
M3Vs7WPZFuHJQljeRCGX/Q1mB87ZtKeA3UobOidD4s4wsGLjtBTBohN+GveOhk/2
d37f7o+GxQIEl/mA+UCcIAECAwEAAQ==
-----END PUBLIC KEY-----
"""

data_to_encrypt = {'Patient ID': 'ssadadsa', 'Date': '2024-06-25', 'Age': 'dsadasd', 'Heart Rate': 'dsada', 'Blood Pressure': 'sdasd',
'Weight': 'sdasd', 'Height': 'sdasd', 'Diagnosis Type': 'Pediatrician', 'Medicines': 'sadd', 'SensitiveData': [{'attribute_name': 'Symptoms', 'ciphertext': 'w1+wEys=', 'tag': 'dHpLHxBVd0ntmJwFvAo/RQ=='}, {'attribute_name': 'Diagnosis', 'ciphertext': 'w1+wEw==', 'tag': 'XI4ycMJrVIZ0qswnh7JXYQ=='}]}

# Test signing
# signature = sign_data(private_key_pem, data_to_encrypt)
# if signature:
#     print(f"Generated Signature: {signature}")
# else:
#     print("Signing failed.")

# # Test verification
# verification_result = verify_signature(public_key_pem, data_to_encrypt, signature)
# if verification_result:
#     print("Signature Verification Result: Successful")
# else:
#     print("Signature verification failed.")

# Test encryption
encrypted_data = encrypt_data(public_key_pem, data_to_encrypt)
if encrypted_data:
    print(f"Encrypted Data: {encrypted_data}")
else:
    print("Encryption failed.")

# Test decryption
if encrypted_data:
    decrypted_data = decrypt_data(private_key_pem, encrypted_data)
    if decrypted_data:
        print("Decrypted Data:")
        print(json.dumps(decrypted_data, indent=4))
    else:
        print("Decryption failed.")

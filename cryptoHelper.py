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

#encrypting_data = ["ONZl1pUOah5wHdT1watUDeR7X+qUWcrWiXaw+9yV8iO5JK5Fm3B8OKQvakoYXVjsnKeFooeEWvjAyA0nViGtf0Fdqfv2rnnfkhYrTHZ4wjkTVCAUQn7wraPJJt0QoL3yIX37MPzUc6rojgBgl/hkjFBgeCr16ZcBM/3c0kvOqGbsxfgl1aTmJNigBe1b2HC2HeGPvV31Nm3v6n273gdnFNpgYCk5rRTxij89F5BeSdqLux6hE2iUqXoBuHxWi/EfjkUvdsqZpjNyQ2hR8MGgswujfiNxIT3bcnUmBA+2qIs4aPh3jpaagWK6KsETxXCuJWqeLT0fZbBfzd4xembNEb4utHXbGDCRnWSZdtYqIQLH8bcuxNEX/Uy44xvE0rLDqC3Av2tUaY6j0XwRxbLVBtYc/rKsR7TsntRqgHBKVU0NiLeHEIkXGJVqijCo/0pY3Am38lOsFANt5waXdrrBqKJIyMOn7M9PI4LG8OTbSvCSdWW9HyIyucdLiecrU016FdouE5DsISR/aoO3JegsDQY/eHoFjZy1lRYzmIV+5BZcPahKS48RErQFgB94xARerOxpw01LoXxYo57Yq5aiBkrpu80nnbYPLAp0+yOD6BReM+sSFS+DVRVktvAOXc0XhTEcf30WTsLZIjXD497I2wuG32UVEX1rzSY0TBxmFRU"]

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
            try:
                encrypted_chunk = base64.b64decode(encrypted_chunk_b64)
                print("encrypted_chunk: ", encrypted_chunk)
                decrypted_chunk = private_key.decrypt(
                    encrypted_chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
                print("decrypted_chunk: ", decrypted_chunk)
            except Exception as inner_e:
                print(f"An error occurred during chunk decryption: {inner_e}")
                return None

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
F2LvzQ2ZVR2dhvLXZc8YZBJUddvb
-----END PRIVATE KEY-----
"""

public_key_pem=""" 
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuHAvrTG/0IXikTW8yyeX
R4zaaF/uiFclfC7lFaxWNdfWdkfo3otQCI0h4h6pH/eyALSIZzVMlPmrqW13hqAE
2TiN/xXsmrMo0rDQIZSk1PrQMvLVnp6s3nHk/lBuO4yW/Zts7zalncrrnZkqtcIC
OkqLYHY7ngQ2R7aW7fQgTxDDjQkTx7YSLI3oeU6RZLCVO2hpEx684TsvRp/uhbZU
91D2EzEv1JAg6uYgNiBO7XBLMra1yPUAEOk5oG5fBSWG9wm9Kko40HaTJ/R+NHsB
W+gNtp/B5eOxSyNLob6EEZO9dxzYE5CxLDM9T6jG46XlK/1w8p6RCwlDm51gOhA6
1Ibb/L7Zil5EY32LX9vp4Yoq90B0rtt9JuA+1kQkyoAD6ZOsvUSSEekQ7rIrFXlK
lMFjd2Q+DjLDFbv2p8gGSOqsBO//7F8+JlFQi8K2id5JZvZSIgOhze7ES5J12nCp
EarAjYD4bxX54QhcCnlsHUxvJiBVjhjtCSvK26AoTLY6xS3lCsELsPvRmhMAfdMY
6yzfaGVphsIu1t0VRGxNdlhsKlg1aiM1bEvAPXCIDMhbTNt3E/Jmirp/h4t+3p/U
M9YL7DgFJb5oWuUudmTK8ZYSCLYfrgmpHy9oFRIUoLG1kme80YFAj2+eEzQe001T
/93b9CwvJdsLq3pP5duNCb8CAwEAAQ==
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

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
import json
import base64
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
        return signature_b64

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
public_key_ssh, public_key_pem, private_key_pem = generate_rsa_key_pair()

data_to_encrypt = {"Patient ID": "sxgujadjkgajkxgsGUGSWDJSBCJQGDUK  HsajxbjAFDSJQGJ", "Date": "2024-06-24", "Age": "sx", "Heart Rate": "sx", "Blood Pressure": "xs", "Weight": "xs", "Height": "sx", "Medicines": "z", "SensitiveData": [{"attribute_name": "Symptoms", "ciphertext": "JQ==", "tag": "JQ=="}, {"attribute_name": "Diagnosis", "ciphertext": "JQ==", "tag": "JQ=="}]}
# Test signing
signature = sign_data(private_key_pem, data_to_encrypt)
if signature:
    print(f"Generated Signature: {signature}")
else:
    print("Signing failed.")

# Test verification
verification_result = verify_signature(public_key_pem, data_to_encrypt, signature)
if verification_result:
    print("Signature Verification Result: Successful")
else:
    print("Signature verification failed.")

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

import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ... [Rest of your existing functions here] ...

# Generate RSA key pairs for two users
user1_private_key, user1_public_key = generate_rsa_key_pair()
user2_private_key, user2_public_key = generate_rsa_key_pair()

# Save private and public keys to files
def save_rsa_key(key, filename, private_key=True):
    if private_key:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

save_rsa_key(user1_private_key, 'user1_private_key.pem')
save_rsa_key(user1_public_key, 'user1_public_key.pem', private_key=False)
save_rsa_key(user2_private_key, 'user2_private_key.pem')
save_rsa_key(user2_public_key, 'user2_public_key.pem', private_key=False)

# ... [Rest of your encryption and file writing logic here] ...

# Sign the ciphertext for both users
signature_user1 = sign_data(user1_private_key, encrypted_data_user1)
signature_user2 = sign_data(user2_private_key, encrypted_data_user2)

# Save signatures to files
with open('signature_user1.bin', 'wb') as file:
    file.write(signature_user1)
with open('signature_user2.bin', 'wb') as file:
    file.write(signature_user2)

# ... [Rest of your decryption logic here] ...

# Verify signatures (Optional step to demonstrate verification)
is_valid_signature_user1 = verify_signature(user1_public_key, signature_user1, encrypted_data_user1)
is_valid_signature_user2 = verify_signature(user2_public_key, signature_user2, encrypted_data_user2)

print("User 1 Signature Valid:", is_valid_signature_user1)
print("User 2 Signature Valid:", is_valid_signature_user2)

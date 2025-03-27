from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64

class SecureKeyManagementSystem:
    def __init__(self):
        # Dictionaries to store symmetric and asymmetric keys
        self.symmetric_keys = {}   # Format: {key_id: AES key (bytes)}
        self.asymmetric_keys = {}  # Format: {user_id: (private_key, public_key)}

    def generate_aes_key(self, key_id: str) -> str:
        """Generate a 256-bit AES key and store it."""
        key = os.urandom(32)  # 256-bit AES key
        self.symmetric_keys[key_id] = key
        return base64.b64encode(key).decode('utf-8')

    def generate_rsa_key_pair(self, user_id: str):
        """Generate an RSA key pair and store it."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        self.asymmetric_keys[user_id] = (private_key, public_key)
        return public_key

    def encrypt_with_aes(self, key_id: str, plaintext: str) -> str:
        """Encrypt plaintext using AES (CBC mode + PKCS7 padding)."""
        key = self.symmetric_keys.get(key_id)
        if not key:
            return plaintext  # Return plaintext if key is missing

        iv = os.urandom(16)  # 128-bit IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_with_aes(self, key_id: str, encrypted_data: str) -> str:
        """Decrypt AES data, return plaintext if key not found."""
        key = self.symmetric_keys.get(key_id)
        if not key:
            return encrypted_data  # Return encrypted text if key is missing

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception:
            return encrypted_data  # Return original encrypted text on error

    def encrypt_with_rsa(self, user_id: str, plaintext: str) -> str:
        """Encrypt using RSA public key, return plaintext if user not found."""
        keys = self.asymmetric_keys.get(user_id)
        if not keys:
            return plaintext  # Return plaintext if user ID not found

        _, public_key = keys
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            asym_padding.PKCS1v15()
        )
        return base64.b64encode(ciphertext).decode('utf-8')

    def decrypt_with_rsa(self, user_id: str, encrypted_data: str) -> str:
        """Decrypt RSA data, return original data if key not found."""
        keys = self.asymmetric_keys.get(user_id)
        if not keys:
            return encrypted_data  # Return encrypted text if user not found

        try:
            private_key, _ = keys
            ciphertext = base64.b64decode(encrypted_data)
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.PKCS1v15()
            )
            return plaintext.decode('utf-8')
        except Exception:
            return encrypted_data  # Return original encrypted text on error

    def generate_diffie_hellman_key(self):
        """Generate Diffie-Hellman parameters and key pair."""
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def key_revocation(self, key_id: str) -> str:
        """Revoke a key (AES or RSA) and return confirmation message."""
        if key_id in self.symmetric_keys:
            del self.symmetric_keys[key_id]
            return "Symmetric key revoked successfully."
        elif key_id in self.asymmetric_keys:
            del self.asymmetric_keys[key_id]
            return "Asymmetric key revoked successfully."
        return "Key ID not found. No action taken."

# ---------------------- Test Cases ----------------------
if __name__ == "__main__":
    kms = SecureKeyManagementSystem()

    # Test AES Encryption & Decryption
    aes_key_id = "user123"
    print("Generating AES key...")
    kms.generate_aes_key(aes_key_id)

    plaintext_aes = "Sensitive Data"
    print("\nEncrypting with AES...")
    aes_encrypted = kms.encrypt_with_aes(aes_key_id, plaintext_aes)
    print("AES Encrypted Data:", aes_encrypted)

    print("\nDecrypting with AES...")
    aes_decrypted = kms.decrypt_with_aes(aes_key_id, aes_encrypted)
    print("AES Decrypted Data:", aes_decrypted)

    # Test RSA Encryption & Decryption
    rsa_user = "userRSA"
    print("\nGenerating RSA key pair...")
    kms.generate_rsa_key_pair(rsa_user)

    plaintext_rsa = "Confidential"
    print("\nEncrypting with RSA...")
    rsa_encrypted = kms.encrypt_with_rsa(rsa_user, plaintext_rsa)
    print("RSA Encrypted Data:", rsa_encrypted)

    print("\nDecrypting with RSA...")
    rsa_decrypted = kms.decrypt_with_rsa(rsa_user, rsa_encrypted)
    print("RSA Decrypted Data:", rsa_decrypted)

    # Test Diffie-Hellman Key Exchange
    print("\nGenerating Diffie-Hellman key pair...")
    dh_private, dh_public = kms.generate_diffie_hellman_key()
    print("Diffie-Hellman Public Key:", dh_public)

    # Test Key Revocation
    print("\nRevoking AES key...")
    revocation_result = kms.key_revocation(aes_key_id)
    print("Revocation Result:", revocation_result)

    # Test AES Decryption After Revocation (Should return encrypted data)
    print("\nAttempting AES decryption after key revocation...")
    aes_decrypted_after_revocation = kms.decrypt_with_aes(aes_key_id, aes_encrypted)
    print("AES Decryption Result After Revocation:", aes_decrypted_after_revocation)

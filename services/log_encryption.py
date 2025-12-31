"""
Log Encryption Service - Encrypts sensitive log data.

"""

from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import base64
import hashlib

load_dotenv()


class LogEncryptionService:
    """
    Handles encryption and decryption of sensitive log data.
    Uses Fernet symmetric encryption (AES-128 in CBC mode).
    """

    def __init__(self):
        # Get encryption key from environment or generate one
        key = os.getenv("LOG_ENCRYPTION_KEY")

        if not key:
            raise ValueError(
                "LOG_ENCRYPTION_KEY not set in environment. "
                "Generate one with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
            )

        # Ensure key is proper format for Fernet (32 url-safe base64-encoded bytes)
        try:
            # If the key is a hex string from secrets.token_hex(32), convert it
            if len(key) == 64:  # Hex string length
                key_bytes = bytes.fromhex(key)
                key = base64.urlsafe_b64encode(key_bytes).decode()

            self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as e:
            raise ValueError(f"Invalid LOG_ENCRYPTION_KEY format: {e}")

    def encrypt(self, data: str) -> str:
        if not data:
            return ""
        try:
            encrypted_bytes = self.cipher.encrypt(data.encode())
            return encrypted_bytes.decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, encrypted_data: str) -> str:
        if not encrypted_data:
            return ""
        try:
            decrypted_bytes = self.cipher.decrypt(encrypted_data.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    @staticmethod
    def hash_sensitive_data(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()


# Singleton instance for easy import
log_encryption_service = LogEncryptionService()

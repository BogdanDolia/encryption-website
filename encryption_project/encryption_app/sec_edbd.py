#!/usr/bin/env python
import os
import base64
import secrets
from typing import Optional, Tuple, Union

# Module-level variable to track Argon2 availability
USE_ARGON2 = False

# Try using Argon2 if available, fall back to PBKDF2 if not
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    USE_ARGON2 = True
except ImportError:
    pass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecureEDBD:
    """
    Class for encryption and decryption using AES-GCM.
    The key is derived from a password using Argon2id (or PBKDF2), which provides resistance to attacks.
    """

    def __init__(self, password: str, salt: Optional[bytes] = None):
        # Check that the password is not empty
        if not password:
            raise ValueError("Password cannot be empty")
            
        # Convert password to bytes
        self.password = password.encode('utf-8')
        # If salt is not provided, generate a cryptographically strong salt (16 bytes)
        self.salt = salt if salt is not None else secrets.token_bytes(16)
        # Derive a cryptographically strong key
        self.key = self.derive_key(self.password, self.salt)

    def derive_key(self, password: bytes, salt: bytes) -> bytes:
        """
        Derives a key from a password using Argon2id or PBKDF2 with HMAC-SHA256.
        """
        global USE_ARGON2
        
        if USE_ARGON2:
            # Try to create Argon2id with different parameter versions
            # First attempt: try a minimal set of parameters that should work with most versions
            try:
                kdf = Argon2id(
                    length=32,  # 256 bits for AES-256
                    salt=salt,
                )
                return kdf.derive(password)
            except Exception:
                # Fallback to PBKDF2 if Argon2 parameters don't match
                USE_ARGON2 = False
                
        # Use PBKDF2 as fallback
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=600000,  # Increased to 600k to compensate for the absence of Argon2
        )
        return kdf.derive(password)

    def encrypt(self, plaintext: str, associated_data: Optional[bytes] = None) -> str:
        """
        Encrypts the plaintext and returns an encrypted message,
        encoded in base64. The result contains salt, nonce, and ciphertext.
        
        Supports associated data for additional authentication.
        """
        if not plaintext:
            raise ValueError("Plaintext cannot be empty")
            
        aesgcm = AESGCM(self.key)
        nonce = secrets.token_bytes(12)  # Cryptographically strong nonce for AES-GCM - 12 bytes
        
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
        
        # Combine salt, nonce, and ciphertext for storage/transmission
        encrypted_message = self.salt + nonce + ciphertext
        return base64.urlsafe_b64encode(encrypted_message).decode('utf-8')

    def decrypt(self, encrypted_message: str, associated_data: Optional[bytes] = None) -> Union[str, None]:
        """
        Decrypts an encrypted message previously obtained using the encrypt method.
        Salt, nonce, and ciphertext are extracted, after which decryption occurs.
        
        Returns None in case of failed authentication or decoding.
        """
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            
            # Check minimum data length (salt + nonce)
            if len(decoded_data) < 28:  # 16 bytes of salt + 12 bytes of nonce
                raise ValueError("Encrypted message is too short")
                
            # Extract salt (16 bytes), nonce (12 bytes), and ciphertext (remaining bytes)
            salt = decoded_data[:16]
            nonce = decoded_data[16:28]
            ciphertext = decoded_data[28:]
            
            # Re-derive the key using the extracted salt - directly use the derive_key method
            key = self.derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext.decode('utf-8')
            
        except (ValueError, InvalidTag, UnicodeDecodeError) as e:
            # Authentication error (data tampering) or decoding error
            return None
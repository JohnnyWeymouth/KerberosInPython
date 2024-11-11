from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_aes_key() -> bytes:
    """
    Generates a random AES key.

    Args:
        key_size (int): The size of the AES key in bytes. Default is 32 bytes for AES-256.

    Returns:
        bytes: The generated AES key.
    """
    return os.urandom(32)

def encrypt_message(key:bytes, plaintext:bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a message using AES encryption with a random IV.

    Args:
        key (bytes): The AES key (must be 32 bytes for AES-256).
        plaintext (bytes): The plaintext to encrypt.

    Returns:
        tuple: A tuple containing the IV and the ciphertext.
    """
    # Generate a random 128-bit IV
    iv = os.urandom(16)

    # Pad the plaintext to be a multiple of the block size (AES block size is 128 bits)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Create AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext

def decrypt_message(key:bytes, iv:bytes, ciphertext:bytes) -> bytes:
    """
    Decrypts a message encrypted with AES encryption.

    Args:
        key (bytes): The AES key (must be 32 bytes for AES-256).
        iv (bytes): The initialization vector (IV) used during encryption.
        ciphertext (bytes): The ciphertext to decrypt.

    Returns:
        bytes: The decrypted plaintext.
    """
    # Create AES cipher in CBC mode with the same IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding from the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
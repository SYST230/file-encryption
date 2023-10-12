# Encryption library for relevant operations on bytes objects

from cryptography.hazmat.primitives import hashes


def caesar_encrypt(data: bytes, key: int) -> bytes:
    """
    Encrypts bytes using a Caesar shift.
    :param data: The bytes to be encrypted.
    :param key: The numerical encryption key.
    :return: The encrypted bytes of data.
    """
    encrypted_data = b''
    for byte in data:
        encrypted_data += ((byte+key) % 256).to_bytes(1, 'little')
    return encrypted_data


def caesar_decrypt(encrypted_data: bytes, key: int) -> bytes:
    """
    Decrypts bytes using a Caesar shift.
    :param encrypted_data: The bytes to be decrypted.
    :param key: The numerical decryption key.
    :return: The decrypted bytes of data.
    """
    recovered_data = b''
    for byte in encrypted_data:
        recovered_data += ((byte - key) % 256).to_bytes(1, 'little')
    return recovered_data


def hash_sha256(data: bytes) -> str:
    """
    Calculate the SHA256 hash of bytes.
    :param data: The bytes to hash.
    :return: The SHA256 hash of the data.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def hash_md5(data: bytes) -> str:
    """
    Calculate the MD5 hash of bytes.
    :param data: The bytes to hash.
    :return: The MD5 hash of the data.
    """
    digest = hashes.Hash(hashes.MD5())
    digest.update(data)
    return digest.finalize().hex()

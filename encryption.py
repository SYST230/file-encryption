# Encryption library for relevant operations on bytes objects

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization


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


def fernet_passwd_encrypt(data: bytes, passwd: bytes) -> bytes:
    """
    Encrypts bytes using Fernet symmetrical encryption, with a key derived from a password.

    :param data: The bytes to be encrypted.
    :param passwd: The bytes password to use for encryption.
    :return: The encrypted bytes of data.
    """
    # Key Derivation Function, to turn the password into a Fernet usable key
    kdf = Scrypt(
        salt=b'salt',  # NOT randomly generated salt. It could be, only if we had a way to store the salt in the file.
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    # Fernet symmetrical encryption
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return encrypted_data


def fernet_passwd_decrypt(encrypted_data: bytes, passwd: bytes) -> bytes:
    """
    Decrypts bytes using Fernet symmetrical encryption, with a key derived from a password.

    :param encrypted_data: The bytes to be decrypted.
    :param passwd: The bytes password to use for decryption.
    :return: The decrypted bytes of data.
    :raises cryptography.fernet.InvalidToken: If the provided password is not correct.
    """
    # Key Derivation Function, to turn the password into a Fernet usable key
    kdf = Scrypt(
        salt=b'salt',  # NOT randomly generated salt. It could be, only if we had a way to store the salt in the file.
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    # Fernet symmetrical decryption
    f = Fernet(key)
    data = f.decrypt(encrypted_data)
    return data


def load_ssh_private_key(key_path: str, password=b''):
    """
    Reads a private key from an OpenSSH-formatted (by default RSA) private key file.

    :param key_path: The path to the private key file.
    :param password: The passphrase to the key file, if needed.
    :return: The private key as a private key object of relevant type.
    """
    with open(key_path, 'rb') as key_file:
        private_key = serialization.load_ssh_private_key(
            key_file.read(),
            password=None if not password else password
        )
    return private_key


def load_ssh_public_key(key_path: str):
    """
    Reads a public key from an OpenSSH-formatted (by default RSA) public key file.

    :param key_path: The path to the public key file.
    :return: The public key as a public key object of relevant type.
    """
    with open(key_path, 'rb') as key_file:
        public_key = serialization.load_ssh_public_key(key_file.read())
    return public_key

# Encryption library for relevant operations on bytes objects

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def setup():
    if not os.path.isdir(os.path.join(os.path.curdir, 'keys')):
        os.mkdir(os.path.join(os.path.curdir, 'keys'))


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


def generate_rsa_keys(key_name: str, path=os.path.join(os.path.curdir, 'keys')):
    """
    Generate a new RSA key pair, saved as files.

    :param key_name: The filename to write to. The public key will be saved as the filename with a .pub extension.
    :param path: The directory to save in. Defaults to 'keys' under the main application directory.
    :return: A tuple of the generated (RSAPrivateKey, RSAPublicKey).
    """
    # Check to see if the path is valid and exists
    if not os.path.isdir(path):
        raise NotADirectoryError
    # Generate the RSA key pair. 65537 is the standard public exponent and 3072 is the default key size of ssh-keygen.
    key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=3072,
    )
    # Convert to bytes of standard file format
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    # Write files
    with open(os.path.join(path, key_name), 'wb') as private_file:
        private_file.write(private_key)
    with open(os.path.join(path, key_name)+'.pub', 'wb') as public_file:
        public_file.write(public_key)
    return key.private_numbers().private_key(), key.public_key()


def rsa_encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypts bytes using RSA asymmetrical encryption with a public key.

    :param data: The bytes to be encrypted.
    :param public_key: An RSAPublicKey object obtained with generate_rsa_keys() or load_ssh_public_key().
    :return: The encrypted bytes of data.
    :raises ValueError: If the given private key is not correct.
    """
    # Secure encryption with padding and hashing
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


def rsa_decrypt(encrypted_data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypts bytes using RSA asymmetrical encryption with a private key.

    :param encrypted_data: The bytes to be decrypted.
    :param private_key: An RSAPrivateKey object obtained with generate_rsa_keys() or load_ssh_private_key().
    :return: The decrypted bytes of data.
    """
    # Identical padding and hashing settings to rsa_encrypt()
    recovered_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return recovered_data


def hmac(passwd: bytes, message: bytes) -> bytes:
    """
    Calculate the HMAC of a message and a key.

    Uses SHA256 and produces a 32-byte HMAC.
    :param passwd: The key.
    :param message: The message.
    :return: The HMAC. Use hmac().hex() for user-readable format.
    """
    BLOCK_SIZE = 64
    if len(passwd) > BLOCK_SIZE:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(passwd)
        passwd_prime = digest.finalize()
    else:
        passwd_prime = passwd
    while len(passwd_prime) < BLOCK_SIZE:
        passwd_prime += b'\x00'
    opad = b'\x5c' * BLOCK_SIZE
    ipad = b'\x36' * BLOCK_SIZE
    part1 = b''
    part2 = b''
    for i in range(BLOCK_SIZE):
        part1 += (passwd_prime[i] ^ opad[i]).to_bytes(1, 'little')
        part2 += (passwd_prime[i] ^ ipad[i]).to_bytes(1, 'little')
    part2 += message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(part2)
    part2 = digest.finalize()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(part1 + part2)
    return digest.finalize()


def aes_encrypt(data: bytes, passwd: bytes):
    """
    Encrypt bytes using AES symmetrical encryption with a password.

    :param data: The bytes to encrypt.
    :param passwd: The bytes password to use for encryption.
    :return: A tuple of the encrypted bytes of data and the random IV used.
    """
    iv = os.urandom(16)
    kdf = Scrypt(
        salt=iv,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(passwd)
    encryptor = Cipher(algorithms.AES(key), modes.XTS(iv)).encryptor()
    if len(data) < 16:
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data, iv


def aes_decrypt(encrypted_data: bytes, passwd: bytes, iv: bytes):
    """
    Decrypt bytes using AES symmetrical encryption with a password.

    :param encrypted_data: The bytes to be decrypted.
    :param passwd: The bytes password to use for decryption.
    :param iv: The IV used, generated during encryption.
    :return: The decrypted bytes of data.
    """
    kdf = Scrypt(
        salt=iv,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(passwd)
    decryptor = Cipher(algorithms.AES(key), modes.XTS(iv)).decryptor()
    recovered_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        recovered_data = unpadder.update(recovered_padded_data) + unpadder.finalize()
    except ValueError as e:
        if str(e) == 'Invalid padding bytes.':
            recovered_data = recovered_padded_data
        else:
            raise e
    return recovered_data


def format_aes(passwd: bytes, encrypted_data: bytes, iv: bytes, file_size: int) -> bytes:
    """
    Given the key, encrypted message, and initialization vector of an AES encryption, assemble an AESCrypt format file.
    Uses AESCrypt Format Version 0.

    :param passwd: The password used to encrypt the data.
    :param encrypted_data: The encrypted data.
    :param iv: The Initialization Vector of the AES algorithm.
    :param file_size: The size of the unencrypted file in bytes.
    :return: The formatted file data.
    """
    # AES File Format version 0, as defined by AES Crypt
    # https://www.aescrypt.com/aes_file_format.html
    data = b'AES\x00'
    data += (file_size % 16).to_bytes(1, 'little')
    data += iv
    data += encrypted_data
    data += hmac(passwd, encrypted_data)
    return data


def unformat_aes(passwd: bytes, filedata: bytes):
    """
    Parse an AES Crypt (version 0) file, extracting usable values from its contents.
    Also uses the HMAC of the file to verify the given password is correct.

    :param passwd: The password used to encrypt the data.
    :param filedata: The formatted file data.
    :return: A 3-tuple of the encrypted file data, the IV, and the unencrypted file size in bytes mod 16.
    """
    if not filedata.startswith(b'AES\x00'):
        raise ValueError('Invalid file format.')
    idx = 4
    file_size_mod_16 = filedata[idx]
    idx += 1
    iv = filedata[idx:idx+16]
    idx += 16
    encrypted_data = filedata[idx:-32]
    if hmac(passwd, encrypted_data) != filedata[-32:]:
        raise ValueError('Invalid password.')
    return encrypted_data, iv, file_size_mod_16


setup()

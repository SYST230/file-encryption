# Library for encrypting and decrypting files from paths

import os
import encryption


def _check_paths(filepath='', folderpath=''):
    """
    Check a path to a file and/or a path to a folder to ensure they are valid.

    :param filepath: The path to the file, optional.
    :param folderpath: The path to the folder, optional.
    :raises FileNotFoundError: If either path is invalid.
    """
    # Raise an error if the file path is given and is not valid
    if filepath != '' and not os.path.isfile(filepath):
        raise FileNotFoundError('The given filepath is invalid.')
    # Raise an error if the target folder is given and does not exist
    if folderpath != '' and not os.path.isdir(folderpath):
        raise FileNotFoundError('The given path does not exist.')


def file_encrypt_caesar(path_to_file: str, key: int, save_location='') -> str:
    """
    Encrypt a file using a Caesar cipher.

    :param path_to_file: The path to the file to encrypt.
    :param key: The numerical key to use for encryption.
    :param save_location: The directory to save the encrypted file under, defaults to '' (same as the original file).
    :return: The path to the encrypted file.
    """
    # Save the encrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        plaintext = f.read()
    # Encrypt the file
    ciphertext = encryption.caesar_encrypt(plaintext, key)
    # Save the encrypted file
    filename = os.path.split(path_to_file)[1]
    target_path = os.path.join(save_location, filename+'.caesar')
    with open(target_path, 'wb') as f:
        f.write(ciphertext)
    # Return the path to the encrypted file
    return target_path


def file_decrypt_caesar(path_to_file: str, key: int, save_location='') -> str:
    """
    Decrypt a file using a Caesar cipher.

    :param path_to_file: The path to the file to decrypt.
    :param key: The numerical key to use for decryption.
    :param save_location: The directory to save the decrypted file under, defaults to '' (same as the original file).
    :return: The path to the decrypted file.
    """
    # Save the decrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        ciphertext = f.read()
    # Decrypt the file
    plaintext = encryption.caesar_decrypt(ciphertext, key)
    # Save the decrypted file
    filename = os.path.split(path_to_file)[1]
    if filename.endswith('.caesar'):
        filename = filename[:-7]
    else:
        filename += '.decrypted'
    target_path = os.path.join(save_location, filename)
    with open(target_path, 'wb') as f:
        f.write(plaintext)
    # Return the path to the decrypted file
    return target_path


def file_hash_sha256(path_to_file: str) -> str:
    """
    Get the SHA256 hash of a file.

    :param path_to_file: The path to the file to hash.
    :return: The hash of the file.
    """
    # Check the validity of the path
    _check_paths(filepath=path_to_file)
    # Read the file
    with open(path_to_file, 'rb') as f:
        contents = f.read()
    # Hash the file and return the hash
    return encryption.hash_sha256(contents)


def file_hash_md5(path_to_file: str) -> str:
    """
    Get the MD5 hash of a file.

    :param path_to_file: The path to the file to hash.
    :return: The hash of the file.
    """
    # Check the validity of the path
    _check_paths(filepath=path_to_file)
    # Read the file
    with open(path_to_file, 'rb') as f:
        contents = f.read()
    # Hash the file and return the hash
    return encryption.hash_md5(contents)


def file_encrypt_fernet(path_to_file: str, password: str, save_location='') -> str:
    """
    Encrypt a file using Fernet symmetrical password encryption.

    :param path_to_file: The path to the file to encrypt.
    :param password: The password for encryption.
    :param save_location: The directory to save the encrypted file under, defaults to '' (same as the original file).
    :return: The path to the encrypted file.
    """
    # Save the encrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        plaintext = f.read()
    # Encrypt the file
    ciphertext = encryption.fernet_passwd_encrypt(plaintext, bytes(password, 'ascii'))
    # Save the encrypted file
    filename = os.path.split(path_to_file)[1]
    target_path = os.path.join(save_location, filename+'.fernet')
    with open(target_path, 'wb') as f:
        f.write(ciphertext)
    # Return the path to the encrypted file
    return target_path


def file_decrypt_fernet(path_to_file: str, password: str, save_location='') -> str:
    """
    Decrypt a file using Fernet symmetrical password encryption.

    :param path_to_file: The path to the file to decrypt.
    :param password: The password for decryption.
    :param save_location: The directory to save the decrypted file under, defaults to '' (same as the original file).
    :return: The path to the decrypted file.
    """
    # Save the decrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        ciphertext = f.read()
    # Decrypt the file
    plaintext = encryption.fernet_passwd_decrypt(ciphertext, bytes(password, 'ascii'))
    # Save the decrypted file
    filename = os.path.split(path_to_file)[1]
    if filename.endswith('.fernet'):
        filename = filename[:-7]
    else:
        filename += '.decrypted'
    target_path = os.path.join(save_location, filename)
    with open(target_path, 'wb') as f:
        f.write(plaintext)
    # Return the path to the decrypted file
    return target_path


def generate_rsa_keys(filename: str, save_location=''):
    # Check the validity of the path
    _check_paths(folderpath=save_location)
    # Make keys
    encryption.generate_rsa_keys(filename, save_location)
    # Return the data
    saved_file_name = os.path.join(save_location, filename)
    return saved_file_name+'.pub', saved_file_name


def file_encrypt_rsa(path_to_file: str, path_to_public_key: str, save_location='') -> str:
    """
    Encrypt a file using RSA asymmetric-key encryption.

    :param path_to_file: The path to the file to encrypt.
    :param path_to_public_key: The path to the public key for encryption.
    :param save_location: The directory to save the encrypted file under, defaults to '' (same as the original file).
    :return: The path to the encrypted file.
    """
    # Save the encrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    _check_paths(filepath=path_to_public_key)
    # Read the file
    with open(path_to_file, 'rb') as f:
        plaintext = f.read()
    # Encrypt the file
    ciphertext = encryption.rsa_encrypt(plaintext, encryption.load_ssh_public_key(path_to_public_key))
    # Save the encrypted file
    filename = os.path.split(path_to_file)[1]
    target_path = os.path.join(save_location, filename+'.rsa')
    with open(target_path, 'wb') as f:
        f.write(ciphertext)
    # Return the path to the encrypted file
    return target_path


def file_decrypt_rsa(path_to_file: str, path_to_private_key: str, save_location='') -> str:
    """
    Decrypt a file using RSA asymmetric-key encryption.

    :param path_to_file: The path to the file to decrypt.
    :param path_to_private_key: The path to the private key for decryption.
    :param save_location: The directory to save the decrypted file under, defaults to '' (same as the original file).
    :return: The path to the decrypted file.
    """
    # Save the decrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    _check_paths(filepath=path_to_private_key)
    # Read the file
    with open(path_to_file, 'rb') as f:
        ciphertext = f.read()
    # Decrypt the file
    plaintext = encryption.rsa_decrypt(ciphertext, encryption.load_ssh_private_key(path_to_private_key))
    # Save the decrypted file
    filename = os.path.split(path_to_file)[1]
    if filename.endswith('.rsa'):
        filename = filename[:-4]
    else:
        filename += '.decrypted'
    target_path = os.path.join(save_location, filename)
    with open(target_path, 'wb') as f:
        f.write(plaintext)
    # Return the path to the decrypted file
    return target_path


def file_encrypt_aes(path_to_file: str, password: str, save_location='') -> str:
    """
    Encrypt a file using AES-256 symmetrical password encryption.

    :param path_to_file: The path to the file to encrypt.
    :param password: The password for encryption.
    :param save_location: The directory to save the encrypted file under, defaults to '' (same as the original file).
    :return: The path to the encrypted file.
    """
    # Save the encrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        plaintext = f.read()
    # Encrypt the file
    ciphertext, iv = encryption.aes_encrypt(plaintext, bytes(password, 'ascii'))
    # Format the encrypted data
    formatted_encrypted_file = encryption.format_aes(bytes(password, 'ascii'), ciphertext, iv, len(plaintext))
    # Save the encrypted file
    filename = os.path.split(path_to_file)[1]
    target_path = os.path.join(save_location, filename+'.aes')
    with open(target_path, 'wb') as f:
        f.write(formatted_encrypted_file)
    # Return the path to the encrypted file
    return target_path


def file_decrypt_aes(path_to_file: str, password: str, save_location='') -> str:
    """
    Decrypt a file using AES-256 symmetrical password encryption.

    :param path_to_file: The path to the file to decrypt.
    :param password: The password for decryption.
    :param save_location: The directory to save the decrypted file under, defaults to '' (same as the original file).
    :return: The path to the decrypted file.
    """
    # Save the decrypted file in the same directory as the original if not otherwise specified
    if save_location == '':
        save_location = os.path.split(path_to_file)[0]
    # Check the validity of the paths
    _check_paths(path_to_file, save_location)
    # Read the file
    with open(path_to_file, 'rb') as f:
        formatted_encrypted_file = f.read()
    # Parse the file
    ciphertext, iv, file_size = encryption.unformat_aes(bytes(password, 'ascii'), formatted_encrypted_file)
    # Decrypt the file
    plaintext = encryption.aes_decrypt(ciphertext, bytes(password, 'ascii'), iv)
    # Check that the size matches
    if len(plaintext) % 16 != file_size:
        raise ValueError('Something went wrong.')
    # Save the decrypted file
    filename = os.path.split(path_to_file)[1]
    if filename.endswith('.aes'):
        filename = filename[:-4]
    else:
        filename += '.decrypted'
    target_path = os.path.join(save_location, filename)
    with open(target_path, 'wb') as f:
        f.write(plaintext)
    # Return the path to the decrypted file
    return target_path

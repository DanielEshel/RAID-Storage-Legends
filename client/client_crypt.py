import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from client.file_manager import *
import os

BLOCK_SIZE = 16  # block size in bytes (128 bits)
LENGTH_SIZE = 6


def encrypt(msg_bytes: bytes, key: bytes):
    """
    encrypts the given bytes with the given key using AES algorithm.
    :param msg_bytes:  msg to encrypt
    :param key: AES encryption key. 256-bit.
    :return:  returns the encrypted message that starts with the initialization vector (bytes).
    """
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # make sure the msg_bytes length is a mul of BLOCK_SIZE. if not, make it by adding NULL bytes at the end.
    bytes_to_add = BLOCK_SIZE - len(msg_bytes) % BLOCK_SIZE
    if bytes_to_add % BLOCK_SIZE:
        msg_bytes += b'\x00'*bytes_to_add  # add something there
    ct = encryptor.update(msg_bytes) + encryptor.finalize()
    return iv+ct


def decrypt(encrypted_bytes: bytes, key: bytes):
    """
    decrypts a message using AES algorithm.
    :param encrypted_bytes: iv + ct of message.
    :param key: AES encryption key. 256-bit.
    :return: returns the decrypted message (bytes).
    """
    iv = encrypted_bytes[:BLOCK_SIZE]
    ct = encrypted_bytes[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    # return the decoded cipher text, strip redundant NULL bytes
    return (decryptor.update(ct) + decryptor.finalize()).rstrip(b'\x00')


def encrypt_file(file_path: str, key: bytes) -> str:
    """
    encrypts an entire file and returns the path of the encrypted file.
    :param file_path: path to file to encrypt.
    :param key: AES encryption key. 256-bit.
    :return: returns the path to the encrypted file.
    """
    if os.path.isfile(file_path):  # make sure path leads to a file.
        iv = os.urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        fs = FS("")
        file = File(file_path)
        file_name = file_path[file_path.rfind('\\')+1:]
        file_size = fs.get_size(file_path)
        encrypted_file = File(f"temp_files\\{file_name}")
        fs.write(encrypted_file, iv)  # write initialization vector to first 16 bytes of file.
        read_bytes = fs.read(file)
        # while not last block in file. reads 2048 bytes max which is a mul of 16. (block size)
        while file.fp.tell() < file_size:
            ct = encryptor.update(read_bytes)
            fs.write(encrypted_file, ct)
            read_bytes = fs.read(file)
        # make sure the msg_bytes length is a mul of BLOCK_SIZE. if not, make it by adding NULL bytes at the end.
        bytes_to_add = BLOCK_SIZE - file_size % BLOCK_SIZE
        if bytes_to_add % BLOCK_SIZE:
            read_bytes += b'\x00' * bytes_to_add  # add something there
        print("length of read bytes: ", len(read_bytes))
        ct = encryptor.update(read_bytes) + encryptor.finalize()
        fs.write(encrypted_file, ct)
        # close files
        fs.close_file(file)
        fs.close_file(encrypted_file)
        return encrypted_file.name  # return encrypted file path.
    else:
        raise ValueError(f'at client_crypt.encrypt_file: could not find file at - {file_path}')


def decrypt_file(file_path: str, key: bytes, save_path):
    """
    decrypts an entire file and saves it in file system.
    :param file_path: path to file to decrypt.
    :param key: AES encryption key (256 bit).
    :param save_path: path to save file at.
    """
    if os.path.isfile(file_path):
        if os.path.exists(save_path):
            fs = FS("")
            file = File(file_path)
            file_name = file_path[file_path.rfind('\\') + 1:]
            file_size = fs.get_size(file_path)
            decrypted_file = File(os.path.join(save_path, file_name))

            read_bytes = fs.read(file, end=BLOCK_SIZE)  # read first 16 bytes to get iv.
            iv = read_bytes[:16]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            ct = fs.read(file)
            print(file.index, file_size, file.size)
            while file.fp.tell() < file_size:
                fs.write(decrypted_file, decryptor.update(ct))
                ct = fs.read(file)
            print(file.index, file_size)
            # strip added buffer from encryption and save to file with finalization.
            fs.write(decrypted_file, (decryptor.update(ct) + decryptor.finalize()).rstrip(b'\x00'))
            fs.close_file(decrypted_file)
            fs.close_file(file)
        else:
            raise ValueError(f'at client_crypt.decrypt_file: could not find path - {file_path}')
    else:
        raise ValueError(f'at client_crypt.decrypt_file: could not find file at - {file_path}')


def get_encrypted_size(file_size: int):
    """
    returns the size that the encrypted file will be.
    :param file_size: size of plain filein bytes.
    :return: the size of the file when encrypted.
    """
    return file_size + BLOCK_SIZE + (BLOCK_SIZE - file_size % BLOCK_SIZE) % BLOCK_SIZE


def get_shared_key(my_socket: socket.socket):
    """
    exchanges public keys with the server and returns the shared key. generates a shared 256-bit AES key.
    :param my_socket: socket to make the exchange with (socket.socket).
    :return: returns the shared key. 256-bit. (bytes)
    """
    try:
        parameters_length = int(my_socket.recv(LENGTH_SIZE).decode())
        parameters_data = my_socket.recv(parameters_length)
    except Exception as e:
        print(e)
    else:
        # Generate parameters.
        parameters = load_pem_parameters(parameters_data)
        # Generate a private key for use in the exchange.
        my_private_key = parameters.generate_private_key()
        my_public_key = my_private_key.public_key()

        # send public key to peer socket.
        public_key_bytes = my_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        length = str(len(public_key_bytes)).zfill(LENGTH_SIZE).encode()

        try:
            my_socket.send(length+public_key_bytes)
            server_key_length = int(my_socket.recv(LENGTH_SIZE).decode())
            server_public_key = my_socket.recv(server_key_length)
        except Exception as e:
            print("big bad exception :( ", e)
        else:
            if server_public_key:
                server_public_key = load_pem_public_key(server_public_key)
                shared_key = my_private_key.exchange(server_public_key)
                # Perform key derivation.
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)
                return derived_key


def main():
    # test file encryption and decryption
    file_path = input()
    key=b'QeThWmZq4t7w!z%C'
    file_size = os.path.getsize(file_path)
    print("file size: ", file_size)
    print('encrypted file size: ', get_encrypted_size(file_size))
    encrypted_file_path = encrypt_file(file_path, key)
    print('actual encrypted file size: ', os.path.getsize(encrypted_file_path))
    decrypt_file(encrypted_file_path, key, os.path.join(os.path.join(os.environ['USERPROFILE']), 'Downloads'))


if __name__ == '__main__':
    main()

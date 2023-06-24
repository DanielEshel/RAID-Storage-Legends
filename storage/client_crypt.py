import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
    # if len(msg_bytes) < BLOCK_SIZE:
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
        server_public_key = None

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
    port = 1234
    server_ip = '127.0.0.1'
    soc = socket.socket()
    soc.connect((server_ip, port))
    key = get_shared_key(my_socket=soc)
    plaintext = 'hello there i am trying to text the encryption and decryption functions.'.encode()
    ct = encrypt(plaintext, key)
    print(f'encrypted message: {ct}')
    pt = decrypt(ct, key)
    print(f'decrypted message: {pt}')


if __name__ == '__main__':
    main()

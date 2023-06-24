import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

BLOCK_SIZE = 16


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
    if bytes_to_add:
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
    if len(encrypted_bytes) % BLOCK_SIZE == 0:
        iv = encrypted_bytes[:BLOCK_SIZE]
        ct = encrypted_bytes[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        # return the decoded cipher text, strip redundant NULL bytes
        return (decryptor.update(ct) + decryptor.finalize()).rstrip(b'\x00')
    else:
        print(len(encrypted_bytes))


def get_shared_key(client_public_key: bytes, parameters, client_socket: socket.socket) -> bytes:
    """
    generates a private and public key. sends to the client the server public key and generates the shared key with the
    client public key.
    :param client_public_key: client's public key.
    :param parameters: Diffie_Hellman parameters. (dh_parameters)
    :param client_socket: client's socket. (socket.socket)
    :return: returns the derived key if exists. else returns None.
    """
    client_public_key = load_pem_public_key(client_public_key)

    # Generate a private key for use in the exchange.
    my_private_key = parameters.generate_private_key()
    my_public_key = my_private_key.public_key()

    # send public key to peer socket.
    public_key_bytes = my_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    length = str(len(public_key_bytes)).zfill(6).encode()
    try:
        client_socket.send(length+public_key_bytes)
    except Exception as e:
        print(e)
    else:
        shared_key = my_private_key.exchange(client_public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=BLOCK_SIZE*2,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key


def send_parameters(client: socket.socket):
    """
    generates the Diffie-Helman parameters and sends them to the client.
    :param client: client's socket (socket.socket)
    :return: the parameters if sent properly. else None.
    """
    # Generate parameters.
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    parameters_data = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
    parameters_length = str(len(parameters_data)).zfill(6).encode()
    try:
        client.send(parameters_length + parameters_data)
    except Exception as e:
        print(e)
    else:
        return parameters


def hash_password(password: str):
    """
    hash a password using SHA3 (256-bit).
    :param password: password to hash (str).
    :return: the hashed bytes. (bytes)
    """
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(password.encode())
    hashed_password = str(digest.finalize())
    return hashed_password


def main():
    soc = socket.socket()
    port = 1234
    soc.bind(('0.0.0.0', port))
    soc.listen(1)
    client, addr = soc.accept()
    print(addr[0], '- connected')
    parameters = send_parameters(client)

    try:
        length = int(client.recv(6).decode())
        client_public_key = client.recv(length)
    except Exception as e:
        print('big bad exception :(', e)
    else:
        if client_public_key:
            key = get_shared_key(client_public_key, parameters, client)
            print(type(key), len(key))
            pt = """
                    hello there my name is Daniel Eshel and this is a top secret message that no one could ever read
                    if they don't have the decryption key.
                """
            print(f'plain text: {pt}')
            ct = encrypt(pt.encode(), key)
            print(f'cipher text: {ct}')
            pt = decrypt(ct, key)
            print(f'plain text: {pt}')


if __name__ == '__main__':
    main()

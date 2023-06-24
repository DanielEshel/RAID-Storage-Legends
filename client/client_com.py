import queue
from client.client_crypt import *
import socket
import threading
from client.file_manager import *


class ClientCom:

    LENGTH_SIZE = 6

    def __init__(self, server_ip: str, port: int, fs=None):
        """
        initializes the client communication object.
        :param server_ip: ip address to connect to.
        :param port: communication port.
        :param fs: file system object.
        """
        self.port = port
        self.server_ip = server_ip
        self.socket = socket.socket()
        self.msg_q = queue.Queue()
        self.fs = fs
        self.key = None
        self.got_key = threading.Event()
        threading.Thread(target=self._main_loop, daemon=True).start()

    def _main_loop(self):
        """
        passes all incoming messages into the msg_q. (messages as bytes).
        """
        try:
            self.socket.connect((self.server_ip, self.port))
        except Exception as e:
            raise e

        self.key = get_shared_key(self.socket)  # get shared encryption key.
        self.got_key.set()

        while True:
            try:
                msg_length = int(self.socket.recv(self.LENGTH_SIZE).decode())
                msg_bytes = self.socket.recv(msg_length)
            except Exception as e:
                print(f'at ClientCom._main_loop: {e}')
                return
            else:
                decrypted_bytes = decrypt(msg_bytes, self.key)
                self.msg_q.put(decrypted_bytes)

    def send(self, msg: str):
        """
        sends a message to the server.
        :param msg: the message to send. (str)
        """
        if self.key is not None:
            data = encrypt(msg.encode(), self.key)
            msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode() + data
            try:
                self.socket.send(msg_to_send)
            except Exception as e:
                print(f'at ClientCom.send: {e}')
                return
        else:
            raise ConnectionError('no encryption key - ClientCom.send')

    def send_file(self, file_path: str):
        """
        sends a file from the file system to the server.
        :param file_path: path to file.
        """
        bytes_sent = 0
        if self.key:
            file = File(file_path)
            data = self.fs.read(file)
            while data is not None:
                data = encrypt(data, self.key)
                msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode()
                try:
                    self.socket.send(msg_to_send)
                    self.socket.send(data)
                except Exception as e:
                    raise e
                bytes_sent += len(data)
                data = self.fs.read(file)

        else:
            raise ConnectionError('no encryption key - ClientCom.send_file')
        print("bytes sent to server upload file: ", bytes_sent)

    def close(self):
        """
        close the com object.
        """
        self.socket.close()


class ClientComFT:
    LENGTH_SIZE = 6

    def __init__(self, server_ip: str, port: int, fs=None, decryption_key=None):
        self.port = port
        self.server_ip = server_ip
        self.socket = socket.socket()
        self.msg_q = queue.Queue()
        self.fs = fs
        self.decryption_key = decryption_key
        self.connected = threading.Event()
        threading.Thread(target=self._main_loop, daemon=True).start()

    def _main_loop(self):
        """
        passes all incoming messages into the msg_q. (messages as bytes).
        """
        try:
            self.socket.connect((self.server_ip, self.port))
        except Exception as e:
            raise e
        self.connected.set()
        while True:
            try:
                msg_length = int(self.socket.recv(self.LENGTH_SIZE).decode())
                msg_bytes = self.socket.recv(msg_length)
            except Exception as e:
                print(f'at ClientCom._main_loop: {e}')
                return
            else:
                if self.decryption_key is not None:
                    msg_bytes = decrypt(msg_bytes, self.decryption_key)
                self.msg_q.put(msg_bytes)

    def send(self, msg: str):
        """
        sends a message to the server.
        :param msg: the message to send. (str)
        """
        data = msg.encode()
        msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode() + data
        try:
            self.socket.send(msg_to_send)
        except Exception as e:
            print(f'at ClientCom.send: {e}')
            return

    def send_file(self, file_path: str):
        """
        sends a file from the file system to the server.
        :param file_path: path to file.
        :return: generates the number of bytes that were sent each time.
        """
        file = File(file_path)
        data = self.fs.read(file)
        while data is not None:
            msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode()
            try:
                self.socket.send(msg_to_send)
                self.socket.sendall(data)
            except Exception as e:
                raise e
            yield len(data)
            data = self.fs.read(file)

    def close(self):
        """
        close the com object.
        """
        self.socket.close()


def main():
    server_ip = '127.0.0.1'
    port = 1234
    fs = FS('T:\\public\\danieleshel')
    file_path = 'dead.txt'
    com = ClientCom(server_ip, port, fs)
    threading.Event.wait(com.got_key)
    print("got enc key")
    com.send_file(file_path)
    print('finished')
    input()


if __name__ == '__main__':
    main()

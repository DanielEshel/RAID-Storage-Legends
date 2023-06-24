import queue
from client.client_crypt import *
import socket
import threading
from client.file_manager import *
from scapy.all import *


class ClientCom:

    LENGTH_SIZE = 6

    def __init__(self, server_ip: str, port: int, fs=None):
        self.port = port
        self.server_ip = server_ip
        self.socket = socket.socket()
        self.msg_q = queue.Queue()
        self.fs = fs
        self.ip_addr = get_if_addr(conf.iface)
        self.key = None
        self.got_key = threading.Event()
        threading.Thread(target=self._main_loop, daemon=True).start()

    def _main_loop(self):
        """
        passes all incoming messages into the msg_q. (messages as bytes).
        """
        try:
            sr1(IP(dst=self.server_ip) / ICMP(type=8), timeout=1)
            time.sleep(1)
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
                data = self.fs.read(file)
        else:
            raise ConnectionError('no encryption key - ClientCom.send_file')

    def close(self):
        """
        close the com object.
        """
        self.socket.close()


class ClientComFT:
    LENGTH_SIZE = 6

    def __init__(self, server_ip: str, port: int, fs=None):
        self.port = port
        self.server_ip = server_ip
        self.socket = socket.socket()
        self.msg_q = queue.Queue()
        self.fs = fs
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
        else:
            self.connected.set()
            while True:
                try:
                    msg_length = int(self.socket.recv(self.LENGTH_SIZE).decode())
                    #msg_bytes = self.socket.recv(msg_length)
                except Exception as e:
                    print(f'at ClientComFT._main_loop: {e}')
                    self.connected.clear()
                    return
                else:
                    file_array = bytearray()
                    while len(file_array) < msg_length:
                        slice = msg_length - len(file_array)
                        if slice > 2048:
                            file_array.extend(self.socket.recv(2048))
                        else:
                            file_array.extend(self.socket.recv(slice))
                            break
                    self.msg_q.put(file_array)

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
            self.connected.clear()
            return

    def send_file(self, file_path: str):
        """
        sends a file from the file system to the server.
        :param file_path: path to file.
        """
        file = File(file_path)
        data = self.fs.read(file)
        while data is not None:
            msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode() + data
            print(str(len(data)).zfill(self.LENGTH_SIZE))
            try:
                self.socket.send(msg_to_send)
            except Exception as e:
                self.connected.clear()
                raise e
            data = self.fs.read(file)

    def close(self):
        """
        close the com object.
        """
        self.socket.close()



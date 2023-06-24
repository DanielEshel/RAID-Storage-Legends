import threading
import socket
import time
import select as s
from server.file_manager import *
from server.server_crypt import *
from cryptography.utils import CryptographyDeprecationWarning
import queue
import warnings
import tqdm
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *


class ServerCom:

    LENGTH_SIZE = 6
    MAX_LENGTH = 3000

    def __init__(self, port: int, fs: FS, banned_ip_addresses: list, allowed_ip_addresses: list, decrypt=True):
        """
        initiates the ServerCom object.
        :param port: server port (int)
        :param fs: file system object.
        :param allowed_ip_addresses: list of allowed ip addresses. True if all are allowed.
        :param banned_ip_addresses: list of all banned ip addresses.
        :param decrypt: bool if to decrypt received data.
        """
        self.port = port
        self.socket = None
        self.msg_q = queue.Queue()
        self.decrypt = decrypt
        self.fs = fs
        self.allowed_ip_addresses = allowed_ip_addresses
        self.banned_ip_addresses = banned_ip_addresses
        self.disconnected_clients = queue.Queue()
        self.open_clients = {}
        threading.Thread(target=self._main_loop, daemon=True).start()

    def _main_loop(self):
        """
        manages client connections.
        """
        self.socket = socket.socket()
        self.socket.bind(('0.0.0.0', self.port))
        self.socket.listen(5)
        while True:
            rlist = self._get_read_sockets()
            for current_client in rlist:
                if current_client is self.socket:
                    try:
                        client, addr = self.socket.accept()
                    except: continue
                    if addr in self.banned_ip_addresses:
                        print('closed: ', client, self.port)
                        client.close()
                    else:
                        # start client-adding thread.
                        threading.Thread(target=self._add_client, args=(client, addr[0],), daemon=True).start()
                else:
                    # try receiving the message length from the client.
                    try:
                        data_length = int(current_client.recv(self.LENGTH_SIZE).decode())
                    except Exception as e:
                        self._disconnect_client(current_client, exception_msg=f'at ServerCom._main_loop: {e}')
                    else:
                        # make sure socket is still sending data
                        if current_client in self._get_read_sockets() and data_length < self.MAX_LENGTH:
                            # try receiving the message length from the client.
                            try:
                                data = current_client.recv(data_length)  # receive data
                            except Exception as e:
                                self._disconnect_client(current_client, exception_msg=f'at ServerCom._main_loop: {e}')
                            else:
                                if self.decrypt:
                                    data = decrypt(data, self.open_clients[current_client][1])  # decrypt data with key.
                                if data is None:
                                    # disconnect and ban client if encryption is wrong
                                    self._disconnect_client(current_client, True)
                                else:
                                    self.msg_q.put((self.open_clients[current_client][0], data))  # add data to queue.

    def _get_read_sockets(self):
        """
        get list of sockets that are available for reading.
        :return: list of sockets that are available for reading.
        """
        try:
            return s.select([self.socket]+list(self.open_clients.keys()), [], [], 1)[0]
        except Exception:
            return []

    def _add_client(self, client: socket.socket, addr: str):
        """
        exchanges keys with client and adds client to the open_clients dictionary.
        :param client: client's socket (socket.socket)
        """
        if addr not in self.allowed_ip_addresses:
            if not (self.allowed_ip_addresses and self.allowed_ip_addresses[0] is True):
                print(f"{addr} banned because not an allowed ip address. port: {self.port}",
                      self.allowed_ip_addresses)
                self.banned_ip_addresses.append(addr)
                client.close()
                return

        dh_params = send_parameters(client)  # get and send diffie hellman parameters to client.
        client.settimeout(5)  # set client receive timeout for 5 seconds
        try:
            length = int(client.recv(self.LENGTH_SIZE).decode())  # get client public key's length
            client_public_key = client.recv(length)  # get client public key
        except Exception:
            print('at ServerCom._add_client closed: ', client, self.port)
            client.close()
        else:
            client.settimeout(None)
            key = get_shared_key(client_public_key, dh_params, client)
            self.open_clients[client] = (addr, key)
            print(f'{addr} - connected to server.')

    def get_encryption_key(self, client_addr: str):
        """
        get the encryption key of a client.
        :param client_addr: ip address of client (str).
        :return: encryption key (bytes)
        """
        client_socket = self._get_socket(client_addr)
        if client_socket is not None:
            key = self.open_clients[client_socket][1]
            return key

    def disconnect_client(self, client_addr, ban=False):
        """
        disconnects a client and removes data.
        :param client_addr: ip v4 address of client.
        :param ban: if to ban client (bool)
        """
        client = self._get_socket(client_addr)
        if client:
            self._disconnect_client(client, ban)

    def _disconnect_client(self, client: socket.socket, ban=False, exception_msg=None):
        """
        disconnects a client and removes data.
        :param client: client socket to remove (socket.socket)
        :param ban: if to ban client (bool)
        """
        if ban:
            self.banned_ip_addresses.append(self.open_clients[client][0])
        if client in self.open_clients:
            self.disconnected_clients.put(self.open_clients[client][0])
            print(f'{self.open_clients[client][0]} {self.port} - disconnected.', end='')
            if exception_msg is not None:
                print(f' -> {exception_msg}')
            else:
                print()

            del self.open_clients[client]
            client.close()

    def send(self, client_addr: str, msg: str):
        """
        sends a message message to a client.
        :param client_addr: ip address of client (str).
        :param msg: msg to send to client (str)
        """
        client = self._get_socket(client_addr)
        if client:
            data = msg.encode()
            self._send(client, data)
        else:
            raise ValueError(f'at ServerCom.send - {client_addr} not connected.')

    def _send(self, client: socket.socket, data: bytes):
        """
        encrypts and sends a message to a client.
        :param client: client's socket (socket.socket)
        :param data: data to send (bytes)
        """
        if client in self.open_clients:  # make sure client is in open_clients.
            data = encrypt(data, self.open_clients[client][1])  # encrypt the message.
            msg_to_send = str(len(data)).zfill(self.LENGTH_SIZE).encode() + data  # add length to message.
            try:
                client.send(msg_to_send)
            except Exception as e:
                print(f'at ServerCom._send - {self.open_clients[client][0]} - {e}')
                self._disconnect_client(client)

    def _get_socket(self, ip_addr):
        """
        get matching socket for client address.
        :param ip_addr: ip address of client (str)
        :return: the matching socket. None if isn't in open_clients.
        """
        keys = [k for k, v in self.open_clients.items() if v[0] == ip_addr]
        if keys:
            return keys[0]

    def is_connected(self, ip_addr):
        """
        check if an ip address is connected as a client.
        :param ip_addr: ip address to check.
        :return: bool as answer.
        """
        return any([ip_addr == ip for ip, key in list(self.open_clients.values())])

    def close(self):
        self.socket.close()


class ServerComStorage(ServerCom):

    def __init__(self, port: int, fs: FS, allowed_mac_addresses: list, banned_ip_addresses: list = None):
        """
        call super class and init the new variables.
        :param port: server port (int)
        :param fs: file system object.
        :param banned_ip_addresses: list of all banned ip addresses.
        :param allowed_mac_addresses: list of allowed mac addresses.
        """
        if banned_ip_addresses is None:
            banned_ip_addresses = []
        super().__init__(port, fs, banned_ip_addresses, [])
        self.open_computers = {}
        self.disconnected_computers = queue.Queue()
        self.allowed_mac_addresses = allowed_mac_addresses
        self.ip_addr = get_if_addr(conf.iface)
        print(self.ip_addr)
        threading.Thread(target=self._add_allowed_ips, daemon=True).start()

    def _filter_p(self, p):
        """
        filter and pass packets that are with the right source mac address and are for the current server.
        :param p: packet.
        :return: if packet passed filter (bool).
        """
        if IP in p and p[IP].dst == self.ip_addr:  # if packet's destination is the server.
            if ICMP in p and p[ICMP].type == 8:  # if an ICMP ping packet
                # if not in banned nor allowed ip address lists
                if p[IP].src not in self.banned_ip_addresses + self.allowed_ip_addresses:
                    print(p[Ether].src, 'pinged server.')
                    if Ether in p and p[Ether].src in self.allowed_mac_addresses:  # if in allowed mac addresses
                        return True
                    else:
                        self.banned_ip_addresses.append(p[IP].src)

        return False

    def _add_allowed_ips(self):
        """
        add the ip addresses of the storage computers if sent a message.
        """
        sniff(lfilter=self._filter_p, prn=self._process_packets)

    def _process_packets(self, p):
        """
        add the ip and mac address of the sender the the lists, and pass to the socket.
        :param p: packet
        """
        print('accepted mac address')
        client_ip_addr = p[IP].src  # extract source ip address from packet
        client_mac_addr = p[Ether].src  # extract source mac address from packet
        self.allowed_ip_addresses.append(client_ip_addr)
        self.open_computers[client_mac_addr] = client_ip_addr

    def send(self, mac_addr: str, msg: str):
        """
        get ip address from mac address and call the father method.
        :param mac_addr: mac address of storage compute (str).
        :param msg: message to send (str).
        :return:
        """
        if mac_addr in self.open_computers:
            ip_addr = self.open_computers[mac_addr]
            ServerCom.send(self, ip_addr, msg)
        else:
            raise ValueError(f'at SeverComStorage.send - {mac_addr} not connected.')

    def disconnect_client(self, mac_addr: str, ban=False):
        """
        remove client from com.
        :param mac_addr: mac address of storage client. (str)
        :param ban: if to ban (bool)
        """
        if mac_addr in self.open_computers:
            ip_addr = self.open_computers[mac_addr]
            del self.open_computers[mac_addr]
            self.allowed_ip_addresses.remove(ip_addr)
            super().disconnect_client(ip_addr, ban)

    def _disconnect_client(self, client: socket.socket, ban=False, exception_msg=None):
        """
        remove from open_computers dict and then call the father method.
        :param client: client's socket (socket.socket)
        :param ban: if to ban (bool).
        """
        if client in self.open_clients:
            ip_addr = self.open_clients[client][0]
            mac_addr = self.get_mac(ip_addr)
            self.disconnected_computers.put(mac_addr)
            if mac_addr is not None:
                del self.open_computers[mac_addr]
            if ip_addr in self.allowed_ip_addresses:
                self.allowed_ip_addresses.remove(ip_addr)
            ServerCom._disconnect_client(self, client, ban, exception_msg)

    def get_mac(self, ip_addr: str):
        """
        get matching mac_address for client address.
        :param ip_addr: ip address of client (str)
        :return: the matching mac_address. None if doesn't exist.
        """
        keys = [k for k, v in self.open_computers.items() if v == ip_addr]
        if keys:
            return keys[0]


class ServerComFT:

    LENGTH_SIZE = 6

    def __init__(self, port: int, fs: FS, banned_ip_addresses: list, allowed_ip_addresses: list):
        """
        initiates the ServerCom object.
        :param port: server port (int)
        :param fs: file system object.
        :param allowed_ip_addresses: list of allowed ip addresses. True if all are allowed.
        :param banned_ip_addresses: list of all banned ip addresses.
        """
        print(port)
        self.port = port
        self.socket = None
        self.msg_q = queue.Queue()
        self.fs = fs
        self.allowed_ip_addresses = allowed_ip_addresses
        self.banned_ip_addresses = banned_ip_addresses
        self.disconnected_clients = queue.Queue()
        self.open_clients = {}
        print(self.allowed_ip_addresses, self.port)
        threading.Thread(target=self._main_loop, daemon=True).start()

    def _main_loop(self):
        """
        manages client connections.
        """
        self.socket = socket.socket()
        self.socket.bind(('0.0.0.0', self.port))
        self.socket.listen(5)
        while True:
            rlist = self._get_read_sockets()
            for current_client in rlist:
                if current_client is self.socket:
                    try:
                        client, addr = self.socket.accept()
                    except Exception as e:
                        print(e)
                    else:
                        if addr[0] not in self.allowed_ip_addresses:

                            if not (self.allowed_ip_addresses and self.allowed_ip_addresses[0] is True):
                                print(f"{addr[0]} banned because not an allowed ip address. port: {self.port}",
                                      self.allowed_ip_addresses)
                                self.banned_ip_addresses.append(addr)
                        if addr in self.banned_ip_addresses:
                            print('closed: ', client, self.port)
                            client.close()
                        else:
                            self.open_clients[client] = addr[0]
                else:
                    # try receiving the message length from the client.
                    try:
                        data_length = current_client.recv(self.LENGTH_SIZE)
                        data_length = int(data_length.decode())
                    except Exception as e:
                        self._disconnect_client(current_client, exception_msg=f'at ServerComFT._main_loop: {e}')
                    else:
                        if current_client in self._get_read_sockets():  # make sure socket is still sending data
                            try:
                                data = current_client.recv(data_length)
                            except Exception as e:
                                self._disconnect_client(current_client,
                                                        exception_msg=f'at ServerComFT._main_loop: {e}, {data_length}')
                            else:
                                print('put in queue: ', len(data))
                                self.msg_q.put((self.open_clients[current_client], data))  # add data to queue.

    def _get_read_sockets(self):
        """
        get list of sockets that are available for reading.
        :return: list of sockets that are available for reading.
        """
        try:
            return s.select([self.socket] + list(self.open_clients.keys()), [], [], 1)[0]
        except Exception as e:
            print('server closed: ', self.port)
            exit()

    def _disconnect_client(self, client: socket.socket, ban=False, exception_msg=None):
        """
        disconnects a client and removes data.
        :param client: client socket to remove (socket.socket)
        :param ban: if to ban client (bool)
        """
        if ban:
            self.banned_ip_addresses.append(self.open_clients[client][0])
        if client in self.open_clients:
            self.disconnected_clients.put(self.open_clients[client][0])
            print(f'{self.open_clients[client][0]} {self.port} - disconnected.', end='')
            if exception_msg is not None:
                print(f' -> {exception_msg}')
            else:
                print()

            del self.open_clients[client]

            client.close()

    def send(self, client_addr: str, msg: bytes):
        """
        sends a message message to a client.
        :param client_addr: ip address of client (str).
        :param msg: msg to send to client (str)
        """
        client = self._get_socket(client_addr)
        if client:
            self._send(client, msg)
        else:
            raise ValueError(f'at ServerCom.send - {client_addr} not connected.')

    def _send(self, client: socket.socket, data: bytes):
        """
        encrypts and sends a message to a client.
        :param client: client's socket (socket.socket)
        :param data: data to send (bytes)
        """
        if client in self.open_clients:  # make sure client is in open_clients.
            print('data: ', len(data), data)
            print('port:', self.port)
            try:
                client.send(str(len(data)).zfill(self.LENGTH_SIZE).encode())
                client.send(data)
            except Exception as e:
                print(f'at ServerCom._send - {self.open_clients[client][0]} - {e}')
                self._disconnect_client(client)

    def send_file(self, client_addr: str, file_path: str, start: int = None, end: int = None):
        """
        sends a file from the file system to the client.
        :param client_addr: client's ip address (str).
        :param file_path: path to file (str).
        :param start: starting index in file (int).
        :param end: ending index in file (int).
        """
        client = self._get_socket(client_addr)
        if client:
            if client in self.open_clients:
                file = File(file_path)
                data = self.fs.read(file, start, end)
                while data is not None:
                    self._send(client, data)  # send encrypted data to client
                    data = self.fs.read(file)  # read new data from file.
        else:
            raise ValueError(f'at ServerCom.disconnect_client - {client_addr} not connected.')

    def _get_socket(self, ip_addr):
        """
        get matching socket for client address.
        :param ip_addr: ip address of client (str)
        :return: the matching socket. None if isn't in open_clients.
        """
        keys = [k for k, v in self.open_clients.items() if v == ip_addr]
        if keys:
            return keys[0]

    def close(self):
        self.socket.close()


def main():
    port = 1234
    allowed_mac_addrs = ['0A-00-27-00-00-02']

    fs = FS(os.path.join(os.path.join(os.environ['USERPROFILE']), 'Downloads'))
    print(fs.path)
    com = ServerComStorage(port, fs, [], allowed_mac_addrs)
    file = File('dst.txt')
    data = com.msg_q.get()
    start = time.time()
    progress = tqdm.tqdm(unit='B', unit_scale=True, unit_divisor=1000, total=1000000000)
    data = data[1]
    length = len(data)
    fs.write(file, data)
    progress.update(len(data))

    while length < 9088:
        data = com.msg_q.get()
        print("got one")
        data = data[1]
        length += len(data)
        fs.write(file, data)
        progress.update(len(data))

    fs.close_file(file)
    print(f'total time: {time.time()-start} seconds.')


if __name__ == '__main__':
    main()

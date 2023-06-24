from server.server_com import *
from server.sp import *
from server.db import *
from server.inputs import *
from server.file_manager import *


class ServerLogic:

    DEFAULT_USER_STORAGE = 1000000000  # 1 gb default storage for new user
    DB_NAME = "data.db"
    FILE_PART_TIMEOUT = 5

    def __init__(self, client_data_port: int = 1111, storage_data_port: int = 2222, file_port_range=(3000, 4000),
                 files_path=''):
        self.fs = FS(files_path)
        self.client_data_port = client_data_port
        self.storage_data_port = storage_data_port
        self.available_ports = list(range(file_port_range[0], file_port_range[1]))
        self.client_data_com = None
        self.storage_data_com = None
        self.banned_ips = None
        self.banned_macs = None
        self.storage_computers = {}
        self.storage_computers_lock = threading.Lock()
        self.users_storage_lock = threading.Lock()
        self.users = {}
        self.users_storage = {}
        self.login_fails = {}
        self.invalid_messages = {}
        self.db = None
        self._start()

    def _start(self):
        """
        start the server. get allowed macs, banned ip addrs from file system and init variables.
        call the _main_logic function.
        """
        with open(os.path.join(self.fs.path, 'banned_ip_addrs.txt'), 'r') as fp:
            self.banned_ips = fp.read().split()

        with open(os.path.join(self.fs.path, 'allowed_mac_addrs.txt'), 'r') as fp:
            self.allowed_macs = fp.read().split()

        self.client_data_com = ServerCom(self.client_data_port, self.fs, self.banned_ips, [True])
        print('allowed mac addresses: ', self.allowed_macs)
        self.storage_data_com = ServerComStorage(self.storage_data_port, self.fs, self.allowed_macs, self.banned_ips)
        threading.Thread(target=self._handle_disconnected_clients, daemon=True).start()
        threading.Thread(target=self._handle_disconnected_storage, daemon=True).start()
        threading.Thread(target=self._handle_storage_data, daemon=True).start()
        self._handle_clients_data()  # main client data process.

    def _handle_clients_data(self):
        """
        main logic for client messages.
        """
        self.db = DB(os.path.join(self.fs.path, ServerLogic.DB_NAME))  # init database

        client_msgs = self.client_data_com.msg_q
        while True:
            client_ip, data = client_msgs.get()
            try:
                data = data.decode()
            except:
                self._remove_client(client_ip, True)
            if len(data) >= 2:  # make sure data format is correct
                opcode, args = unpack(data)

                if opcode == '00':  # add new user
                    if len(args) == 2:
                        username, password = args
                        self._login_user(client_ip, username, password)
                    else:
                        self._add_invalid_message(client_ip)
                        self._remove_client(client_ip)

                elif opcode == '01':  # sign up user
                    if len(args) == 2:
                        username, password = args
                        self._register_user(client_ip, username, password)
                    else:
                        self._add_invalid_message(client_ip)
                        self._remove_client(client_ip)

                elif opcode == '02':  # send file list to user
                    self._send_files_list(client_ip)

                elif opcode == '03':  # send storage data to user
                    self._send_storage_data(client_ip)

                elif opcode == '04':  # reply to upload request.
                    if len(args) == 2:
                        file_name, file_size = args
                        self._handle_client_upload_request(client_ip, file_name, file_size)
                    else:
                        self._add_invalid_message(client_ip)
                        self._remove_client(client_ip)
                elif opcode == '05':  # reply to download request.
                    if len(args) == 1:
                        file_name = args[0]
                        self._handle_client_download_request(client_ip, file_name)
                elif opcode == '06':  # client wants to delete file
                    if len(args) == 1:
                        file_name = args[0]
                        self._delete_file(client_ip, file_name)
                    else:
                        self._add_invalid_message(client_ip)
                        self._remove_client(client_ip)
                elif opcode == '07':  # client wants to log out
                    self._logout_user(client_ip)

            else:
                self._add_invalid_message(client_ip)
                self._remove_client(client_ip)

    def _handle_storage_data(self):
        """
        main logic for storage computer messages.
        """
        db = DB(os.path.join(self.fs.path, ServerLogic.DB_NAME))

        known_storage_computers = db.get_storage_computers()
        storage_msgs = self.storage_data_com.msg_q
        print("known storage computers: ", known_storage_computers)
        while True:
            storage_ip, data = storage_msgs.get()
            try:
                data = data.decode()
            except:
                self._remove_storage(self.storage_data_com.open_computers[storage_ip])
            storage_mac = self.storage_data_com.get_mac(storage_ip)

            opcode, args = unpack(data)
            if opcode == '00':  # storage computer wants to connect.
                if len(args) == 2 and all([arg.isdigit() for arg in args]):
                    new_allocated, new_used = int(args[0]), int(args[1])
                    with self.storage_computers_lock:
                        self.storage_computers[storage_mac] = new_allocated, new_used
                        if storage_mac in known_storage_computers:
                            allocated, used = known_storage_computers[storage_mac]
                            if new_allocated != allocated or new_used != used:
                                self._clear_storage_computer(storage_mac, new_allocated, db)
                                known_storage_computers[storage_mac] = new_allocated, 0
                            else:
                                self.storage_computers[storage_mac] = allocated, used
                            print(f"connected {storage_mac} as storage computer")
                            contained_blocks = db.get_contained_files(storage_mac)  # get all blocks contained
                            for block in contained_blocks:
                                file_name = block[:-4]
                                if not db.file_exists(file_name):  # if file was deleted but block was not.
                                    self.storage_data_com.send(storage_mac, get_file_deletion_msg(block))
                                    db.remove_block(block)
                        else:
                            db.add_storage_computer(storage_mac, new_allocated, new_used)
                            print(f"added {storage_mac} to database")
                            known_storage_computers[storage_mac] = new_allocated, new_used
                            self.storage_computers[storage_mac] = new_allocated, new_used
                else:
                    self._remove_storage(storage_mac)

    def _handle_disconnected_storage(self):
        """
        handle disconnectino of storage computer
        """
        while True:
            self.storage_data_com.disconnected_clients.get()
            storage_mac = self.storage_data_com.disconnected_computers.get()
            print(f'{storage_mac} - disconnected')
            with self.storage_computers_lock:
                del self.storage_computers[storage_mac]

    def _handle_disconnected_clients(self):
        """
        handle disconnection of client
        """
        while True:
            client_ip = self.client_data_com.disconnected_clients.get()
            self._remove_client_data(client_ip)

    def _get_port(self, client_ip='localhost'):
        """
        get a non-taken port from the port range.
        :return: port number (int)
        """
        while True:
            if self.available_ports:
                port = self.available_ports.pop()
                return port
            else:
                return None

    def _logout_user(self, ip_addr):
        """
        log out a user.
        :param ip_addr: ip address of client
        """
        if ip_addr in self.users:
            username = self.users.pop(ip_addr)  # get and remove client address from users dict
            with self.users_storage_lock:
                del self.users_storage[username]
            print(username, 'logged out!')
        else:
            self._remove_client(ip_addr)

    def _delete_file(self, ip_addr, file_name):
        """
        delete a file
        :param ip_addr: client's ip address. (str)
        :param file_name: file name to delete.
        """
        answer = '0'
        if ip_addr in self.users:
            username = self.users[ip_addr]
            system_file_name = ServerLogic._generate_user_filename(file_name, username)
            if self.db.file_exists(system_file_name):
                blocks = self.db.get_file_blocks(system_file_name)
                file_size = self.db.get_size(system_file_name)
                number_of_blocks, blocks_without_extra_byte = self.db.get_number_of_blocks(system_file_name)
                block_size = (file_size + number_of_blocks - blocks_without_extra_byte) // number_of_blocks
                for block_name, mac_addr in blocks:
                    if mac_addr in self.storage_computers:
                        with self.storage_computers_lock:
                            allocated, used = self.storage_computers[mac_addr]
                            used -= block_size
                            self.storage_computers[mac_addr] = allocated, used
                            self.db.update_storage_data(mac_addr, new_used=used)
                        self.storage_data_com.send(mac_addr, get_file_deletion_msg(block_name))
                        self.db.remove_block(block_name)  # remove block name from db only if computer is connected.

                with self.users_storage_lock:
                    allocated, used = self.users_storage[username]
                    used -= file_size
                    self.db.update_user_storage(username, new_used=used)
                self.db.remove_file(system_file_name)  # delete from database

                print(f"{file_name} deleted")
                answer = '1'
            self.client_data_com.send(ip_addr, get_file_deletion_request_reply(file_name, answer))
        else:
            self._remove_client(ip_addr)

    def _clear_storage_computer(self, mac_addr, allocated_storage, db):
        """
        remove data of storage computer and add as new storage computer.
        :param mac_addr: mac address of storage computer (str).
        :param allocated_storage: allocated storage for storage computer.
        :return:
        """
        for file_name in db.get_contained_files(mac_addr):  # make storage computer delete all known files
            deletion_msg = get_file_deletion_msg(file_name)
            self.storage_data_com.send(mac_addr, deletion_msg)

        db.remove_storage_computer(mac_addr)
        db.add_storage_computer(mac_addr, allocated_storage, 0)

    def _add_invalid_message(self, ip_addr):
        """
        inc invalid message counter to ip address.
        :param ip_addr: ip address of client.
        """
        if ip_addr in self.invalid_messages:
            self.invalid_messages[ip_addr] += 1
        else:
            self.invalid_messages[ip_addr] = 1

    def _remove_client(self, ip_addr, ban=False, exception_msg=None):
        """
        remove a client from the server.
        :param ip_addr: ip address of client (str).
        """

        if ip_addr in self.invalid_messages:
            if self.invalid_messages[ip_addr] > 10:
                del self.invalid_messages[ip_addr]  # remove from list.
                ban = True  # ban ip address. (spamming invalid messages)

        if ip_addr in self.users:  # if connected as user, log user out.
            self._logout_user(ip_addr)

        self.client_data_com.disconnect_client(ip_addr, ban)

    def _remove_client_data(self, ip_addr):
        """
        remove client's data from server.
        :param ip_addr: ip address of client.
        """
        if ip_addr in self.users:
            username = self.users.pop(ip_addr)
            with self.users_storage_lock:
                del self.users_storage[username]
            print(f'{username} - logged out!')

    def _remove_storage(self, mac_addr, ban=False):
        """
        remove a storage computer from the server.
        :param mac_addr: mac address of storage computer (str).
        """
        if mac_addr in self.storage_computers:
            with self.storage_computers_lock:
                del self.storage_computers[mac_addr]
        self.storage_data_com.disconnect_client(mac_addr, ban)

    def _login_user(self, ip_addr, username, password):
        """
        log in to existing user.
        :param username: username (str).
        :param password: password (str).
        :return:
        """
        answer_code = '0'
        if valid_username(username) and valid_password(password):
            if self.db.user_exists(username):  # check if username exists
                password = hash_password(password)  # get password hash
                if self.db.check_password(username, password):  # verify password with database
                    if username in self.users.values():  # if user already logged in, disconnect logged ip address.
                        logged_ip = [k for k, v in self.users.items() if v == username][0]
                        self._remove_client(logged_ip)

                    allocated, used = self.db.get_storage_data(username)  # get user storage data
                    self.users[ip_addr] = username
                    self.users_storage[username] = allocated, used
                    if (username, ip_addr) in self.login_fails:
                        del self.login_fails[(username, ip_addr)]
                    answer_code = '1'
                    print(f'{username} - logged in!')
        else:
            answer_code = '2'
        if answer_code != '1':  # if login failed
            if ip_addr not in self.login_fails:
                self.login_fails[(username, ip_addr)] = 1
            elif self.login_fails[(username, ip_addr)] > 10:
                self._remove_client(ip_addr, ban=True)
                del self.login_fails[(username, ip_addr)]
            else:
                self.login_fails[(username, ip_addr)] += 1
        self.client_data_com.send(ip_addr, get_login_reply(answer_code))  # send login reply to client

    def _register_user(self, ip_addr, username, password):
        """
        register a new user.
        :param ip_addr: ip address (str).
        :param username: username (str).
        :param password: password (str).
        """
        answer_code = '2'
        if valid_username(username) and valid_password(password):
            if ip_addr not in self.users:
                if not self.db.user_exists(username):  # check if username doesnt exists
                    password = hash_password(password)  # get password hash
                    allocated, used = ServerLogic.DEFAULT_USER_STORAGE, 0
                    self.db.add_user(username, password, allocated, used)  # add user to database.
                    self.users[ip_addr] = username
                    self.users_storage[username] = allocated, used
                    answer_code = '1'
                    print(f'{username} - logged in!')
                else:
                    answer_code = '0'
            else:
                if self.users[ip_addr] == username:
                    password = hash_password(password)  # get password hash
                    self.db.change_password(username, password)
                    answer_code = '1'
        self.client_data_com.send(ip_addr, get_user_info_update_reply(answer_code))  # send login reply to client

    def _send_files_list(self, ip_addr):
        """
        send file names and lengths to user.
        :param ip_addr: ip address of client (str)
        """
        if ip_addr in self.users:  # make sure client is logged in.
            username = self.users[ip_addr]  # get username.
            files = self.db.get_belonging_files(username)
            for name in files:
                size = files.pop(name)
                files[self._strip_system_filesname(name, username)] = size
            self.client_data_com.send(ip_addr, get_files_data_msg(files))  # send files message to client.
        else:
            self._remove_client(ip_addr)  # remove and ban client if not logged in yet.

    def _send_storage_data(self, ip_addr):
        """
        send storage status to user.
        :param ip_addr: ip address of client (str)
        """
        if ip_addr in self.users:  # make sure client is logged in.
            username = self.users[ip_addr]  # get username.
            allocated, used = self.users_storage[username]
            self.client_data_com.send(ip_addr, get_user_storage_msg(allocated, used))  # send files message to client.
        else:
            self._remove_client(ip_addr)  # remove and ban client if not logged in yet.

    def _handle_client_upload_request(self, ip_addr, file_name, file_size):
        """
        answer client's file upload request.
        :param ip_addr: ip address of client
        :param file_name: name of file.
        :param file_size: size of file.
        """

        file_name = file_name.strip()
        if ip_addr in self.users:
            if valid_file_name(file_name) and file_size.isdigit() and int(file_size) > 0:
                file_size = int(file_size)
                username = self.users[ip_addr]
                print(f'{username} wants to upload a file!')
                allocated, used = self.users_storage[username]
                file_save_name = ServerLogic._generate_user_filename(file_name, username)
                if file_size <= allocated - used:
                    if not self.db.file_exists(file_save_name):
                        port = self._get_port(ip_addr)
                        if port is not None and self.storage_computers:
                            # start file upload thread.
                            threading.Thread(target=self._handle_client_upload,
                                             args=(ip_addr, file_save_name, file_size,
                                                   port,)).start()
                            # send answer to client
                            self.client_data_com.send(ip_addr, get_upload_request_reply(file_name, '1', port))
                            print(f'{username} starting file upload')
                            return
                        else:
                            answer_code = '3'
                    else:
                        answer_code = '0'
                else:
                    answer_code = '2'
                self.client_data_com.send(ip_addr, get_upload_request_reply(file_name, answer_code))

            else:
                self._add_invalid_message(ip_addr)
                self._remove_client(ip_addr)

    def _handle_client_upload(self, ip_addr, file_name, file_size, port):
        """
        handle user's file upload.
        :param ip_addr: ip address of client.
        :param file_name: name of file.
        :param file_size: size of file in bytes.
        :param port: port to receive data from.
        """
        upload_com = ServerComFT(port, self.fs, banned_ip_addresses=self.banned_ips, allowed_ip_addresses=[ip_addr])
        
        print("file save size: 11", file_size)
        file = File(f'temp_files\\{file_name}')
        length = 0
        while length < file_size:
            try:
                data = upload_com.msg_q.get(timeout=ServerLogic.FILE_PART_TIMEOUT)
            except Exception:
                self._remove_client(ip_addr)
                self.fs.close_file(file)
                self.fs.delete(file.name)
                return
            else:
                data = data[1]
                length += len(data)
                self.fs.write(file, data)
        self.fs.close_file(file)
        key = self.client_data_com.get_encryption_key(ip_addr)  # get encryption key of file.
        upload_com.send(ip_addr, get_file_transfer_complete_msg('1'))  # send confirmation message to client.
        upload_com.close()
        print('open clients for file upload: ', upload_com.open_clients)
        threading.Thread(target=self._split_file, args=(file_name, file_size, port, ip_addr, key), daemon=True).start()

    def _get_storage_computers(self, file_size):
        """
        get list of storage computers that can store a given file size.
        :param file_size: size of file in bytes (str).
        :return: mac addresses of storage computers to store the file. (list)
        """
        file_size *= 2  # total file size is doubled when stored for redundancy.
        with self.storage_computers_lock:
            storage_computers = self.storage_computers.copy()  # make a copy of storage computers dict.
        print('\nstorage computers at get storage computers: ', storage_computers, self.storage_computers, '\n')
        number_of_computers = len(storage_computers)
        storage_computers = sorted(storage_computers.items(), key=lambda x: x[1][0] - x[1][1], reverse=True)
        # make sure odd number of storage computers or less than 5
        if number_of_computers > 5 and number_of_computers % 2:
            number_of_computers -= 1
            storage_computers.pop()  # remove last item from list (smallest

        got_computers = False
        while number_of_computers > 0 and not got_computers:
            got_computers = True
            for mac_addr, (total, used) in storage_computers:
                space_left = total - used
                if space_left < file_size // number_of_computers:
                    if number_of_computers <= 5:
                        number_of_computers -= 1
                    else:
                        number_of_computers -= 2

                    del storage_computers[mac_addr]
                    got_computers = False
                    break

        return [computer[0] for computer in storage_computers]

    @staticmethod
    def _byte_xor(a: bytes, b: bytes):
        """
        xor between two bytes objects.
        :return: return the result.
        """
        return bytes([_a ^ _b for _a, _b in zip(a, b)])

    @staticmethod
    def _get_parity_blocks(number_of_blocks):
        """
        get dictionary of each computer index and a list representing the parity.
        :param number_of_blocks: number of storage computers to split the file into.
        :return: return the dictionary.
        """
        if number_of_blocks > 1:  # only make parity blocks when there's more than one storage computer.
            parity_blocks = {}  # dictionary of parity blocks
            # for every data block, make a matching parity block that has the n//2 next blocks
            for index in range(number_of_blocks):
                parity_blocks[index] = [str((index + 1) % number_of_blocks).zfill(2)]
                for j in range(2, number_of_blocks // 2 + 1):
                    computer_index = (index + j) % number_of_blocks
                    if index in parity_blocks.keys():
                        parity_blocks[index].append(str(computer_index).zfill(2))

            return parity_blocks

    @staticmethod
    def _generate_user_filename(file_name, username):
        """
        generate a user's file name as saved in the system.
        :param file_name: original name of file. (str)
        :param username: username (str).
        :return: return the file name as saved in the system.
        """
        return f'{username} {file_name} {username}'

    @staticmethod
    def _strip_system_filesname(file_name, username):
        """
        strips the username from a file name.
        :param file_name:
        :param username:
        :return:
        """
        split_name = file_name.strip().split()
        name = ''
        for word in list(split_name):
            if word.strip() != username:
                name += word + ' '
        return name.strip()

    def _split_file(self, file_name, file_size, port, ip_addr, key):
        """
        split file bytes to given number of computers.
        :param file_name: name of file (str).
        :param file_size: size of file in bytes.
        :param ip_addr: ip address of client that
        """

        def get_transfer_confirmation(com, number_of_files, timeout):
            print('number of files in this place: ', number_of_files)
            for x in range(number_of_files):  # get confirmation from every storage computer
                try:
                    sender, answer_msg = com.msg_q.get(timeout=timeout)
                    answer_msg = answer_msg.decode()
                except Exception as e:
                    return False
                else:
                    if answer_msg != '1':
                        return False

            return True
        print('file save size at split filel: ', file_size)
        db = DB(name=os.path.join(self.fs.path, ServerLogic.DB_NAME))
        storage_computers = self._get_storage_computers(file_size)
        print(storage_computers)
        if storage_computers:
            computers = {}
            for mac_addr in storage_computers:
                computers[mac_addr] = self.storage_data_com.open_computers[mac_addr]

            number_of_blocks = len(storage_computers)
            block_size = file_size // number_of_blocks  # size of each block
            excess_bytes = (number_of_blocks - file_size % number_of_blocks) % number_of_blocks
            block_save_size = (file_size + excess_bytes) // number_of_blocks
            print("block save size: ", block_save_size)
            # open storage com object to connect to storage computers.
            files_com = ServerComFT(port=port, fs=self.fs, banned_ip_addresses=[],
                                    allowed_ip_addresses=list(computers.values()))
            # send upload notice message to storage computes
            for index, mac_addr in enumerate(storage_computers):
                name = f'{file_name} D{str(index).zfill(2)}'
                try:
                    self.storage_data_com.send(mac_addr,
                                               get_file_upload_notice_msg(file_name=name, file_size=block_save_size,
                                                                          port=port))
                except Exception:
                    self.client_data_com.send(ip_addr, get_file_transfer_complete_msg('0'))
                    return

            for mac_addr in storage_computers:
                while True:
                    if computers[mac_addr] in files_com.open_clients.values():
                        break

            block_files = {}
            file = File('temp_files' + '\\' + file_name)  # get file object
            for index, (mac_addr, storage_ip) in enumerate(computers.items()):  # send data blocks to storage computers
                name = f'{file.name} D{str(index).zfill(2)}'
                block_files[index] = File(name)
                # send block to storage computer

                if number_of_blocks - excess_bytes <= index:
                    print('added an extra byte at ', index,
                          index * block_save_size - excess_bytes + number_of_blocks -
                          index, (index + 1) * block_save_size - excess_bytes + number_of_blocks -
                          index - 1)

                    # save block as new file.
                    read_data = b'a' + self.fs.read(file,
                                                    start=index * block_save_size - excess_bytes + number_of_blocks -
                                                    index,
                                                    end=(index + 1) * block_save_size - excess_bytes + number_of_blocks -
                                                    index - 1)

                    while read_data is not None:
                        files_com.send(storage_ip, read_data)
                        self.fs.write(block_files[index], read_data)
                        read_data = self.fs.read(file,
                                                 start=index * block_save_size - excess_bytes + number_of_blocks -
                                                 index,
                                                 end=(index + 1) * block_save_size - excess_bytes + number_of_blocks -
                                                 index - 1)
                else:
                    print('didnt add an extra byte at: ', index, index*block_save_size, (index+1) * block_save_size)
                    # save block as new file.
                    read_data = self.fs.read(file, start=index * block_save_size, end=(index + 1) * block_save_size)
                    while read_data is not None:
                        files_com.send(storage_ip, read_data)
                        self.fs.write(block_files[index], read_data)
                        read_data = self.fs.read(file, start=index * block_save_size, end=(index + 1) * block_save_size)

                self.fs.close_file(block_files[index])  # close file after wrote all block data

            self.fs.close_file(file)

            timeout = 5 + (block_size // 1000) // 50
            uploaded = get_transfer_confirmation(files_com, number_of_blocks, timeout)
            print('uploaded: ', uploaded)
            parity_block_names = self._get_parity_blocks(number_of_blocks)
            parity_files = {}

            if uploaded:
                if parity_block_names is not None:

                    files_com.close()
                    files_com = ServerComFT(port=port, fs=self.fs, banned_ip_addresses=[],
                                            allowed_ip_addresses=list(computers.values()))

                    for parity_index in parity_block_names:
                        # open a file for each parity block.
                        parity_files[parity_index] = File(f'{file.name} P{str(parity_index).zfill(2)}')
                        # send notice msg for each parity file.
                        self.storage_data_com.send(storage_computers[parity_index],
                                                   get_file_upload_notice_msg(file_name=f'{file_name}'
                                                                                        f' P{str(parity_index).zfill(2)}',
                                                                              file_size=block_size, port=port))
                    for mac_addr in storage_computers:
                        while True:
                            if computers[mac_addr] in files_com.open_clients.values():
                                break

                    while True:
                        blocks_data = {}  # file read data of each block
                        for i in range(number_of_blocks):  # read a block of data from each file
                            read_data = self.fs.read(block_files[i])  # read from block file
                            if read_data is None:  # if EOF
                                blocks_data = None
                                break
                            blocks_data[i] = read_data
                        if blocks_data is None:  # if end of block file.
                            for index, block_file in parity_files.items():  # close and send all files.
                                self.fs.close_file(block_file)
                                try:
                                    threading.Thread(target=files_com.send_file,
                                                     args=(computers[storage_computers[index]],
                                                           parity_files[index].name), daemon=True).start()
                                except Exception:
                                    self.client_data_com.send(ip_addr, get_file_transfer_complete_msg('0'))
                            break

                        else:
                            for index, parity_blocks in parity_block_names.items():
                                # make parity
                                parity = blocks_data[int(parity_blocks[0])]
                                for block_name in parity_blocks[1:]:
                                    parity = ServerLogic._byte_xor(parity, blocks_data[int(block_name)])
                                self.fs.write(parity_files[index], parity)  # write parity to parity file
                    uploaded = get_transfer_confirmation(files_com, number_of_blocks, timeout)

            if not uploaded:  # handle fail
                self.client_data_com.send(ip_addr, get_file_transfer_complete_msg('0'))  # send fail message to client.
                for index, block_file in list(block_files.items()) + list(parity_files.items()):
                    mac_addr = storage_computers[index]
                    self.storage_data_com.send(mac_addr, get_file_deletion_msg(block_file.name))

            else:
                print('uploaded a file')
                for index, block_file in list(block_files.items()) + list(parity_files.items()):
                    mac_addr = storage_computers[index]
                    db.add_block(block_file.name[11:], mac_addr)
                    with self.storage_computers_lock:
                        allocated, used = self.storage_computers[mac_addr]
                        used += block_size
                        self.storage_computers[mac_addr] = allocated, used
                        db.update_storage_data(mac_addr, new_used=used)

                without_extra_byte = number_of_blocks - excess_bytes
                db.add_file(file_name, number_of_blocks, without_extra_byte, file_size, key)
                if ip_addr in self.users:
                    username = self.users[ip_addr]
                    with self.users_storage_lock:  # change user's storage status
                        allocated, used = self.users_storage[username]
                        used += file_size
                        self.users_storage[username] = allocated, used
                        db.update_user_storage(username, new_used=used)

                    print(f'{username} uploaded a file!')
                    # send confirmation message to client.
                    self.client_data_com.send(ip_addr, get_file_transfer_complete_msg('1',
                                                                                      self._strip_system_filesname(
                                                                                          file_name, username)))

            # close and delete all temp files
            for index, block_file in list(block_files.items()) + list(parity_files.items()):
                block_name = block_file.name
                self.fs.close_file(block_file)
                self.fs.delete(block_name)

            self.fs.close_file(file)
            self.fs.delete(file.name)
            files_com.close()  # close com.

        self.fs.delete(file_name)  # delete temp file if still exists
        self.available_ports.append(port)  # return port

    def _handle_client_download_request(self, ip_addr, file_name):
        """
        handle a client's file download request.
        :param ip_addr: ip address of client. (str)
        :param file_name: file name to download. (str)
        """
        db = DB(name=os.path.join(self.fs.path, ServerLogic.DB_NAME))
        if ip_addr in self.users:
            username = self.users[ip_addr]
            system_file_name = ServerLogic._generate_user_filename(file_name, username)
            if db.file_exists(system_file_name):

                print(f'{username} wants to download {file_name}')
                file_blocks = db.get_file_blocks(system_file_name)

                blocks = {}
                for block_info in file_blocks:
                    block_name, mac_addr = block_info
                    blocks[block_name] = mac_addr

                file_block_info = db.get_number_of_blocks(system_file_name)
                key = db.get_encryption_key(system_file_name)
                number_of_blocks, blocks_without_extra_byte = file_block_info

                for file, mac_addr in list(blocks.items()):
                    with self.storage_computers_lock:
                        if mac_addr not in self.storage_data_com.open_computers:
                            print(mac_addr, self.storage_data_com.open_computers)
                            del blocks[file]

                print(len(blocks), number_of_blocks)
                if len(blocks) // 2 > number_of_blocks // 2 or \
                        (number_of_blocks < 5 and len(blocks) // 2 >= number_of_blocks / 2) or \
                        (number_of_blocks == 1 and len(blocks) == 1):
                    print('starting download!')
                    port = self._get_port(ip_addr)
                    threading.Thread(target=self._handle_client_download,
                                     args=(ip_addr, port, system_file_name, blocks, number_of_blocks,
                                           blocks_without_extra_byte)).start()
                    self.client_data_com.send(ip_addr, get_download_request_msg(file_name, '1', port, key.hex()))

                else:
                    self.client_data_com.send(ip_addr, get_download_request_msg(file_name, '2'))

            else:
                self.client_data_com.send(ip_addr, get_download_request_msg(file_name, '0'))

        else:
            self._remove_client(ip_addr)

    def receive_blocks(self, com, blocks, block_size, computers):
        """
        receive blocks from storage computers.
        :param com: com to receive blocks from
        :param blocks: blocks to receive
        :param block_size: size of block
        :param computers: storage computers dict
        :return: return the block files that have been saved in the file system.
        """
        print(f'\nblock size at receive blocks: {block_size}\n')
        blocks_to_receive = len(blocks)
        block_files = {}
        while blocks_to_receive > 0:
            ip, data = com.msg_q.get()
            mac_addr = self.storage_data_com.get_mac(ip)
            block_name = computers[mac_addr]
            if block_name not in block_files:
                block_files[block_name] = File(f'temp_files\\'
                                               f'{[name for name, mac in blocks.items() if mac == mac_addr][0]}')
            f = block_files[block_name]
            self.fs.write(f, data)
            if f.index == block_size:
                blocks_to_receive -= 1
                self.fs.close_file(f)

        for mac_addr in blocks.values():
            # send confirmation code to all storage clients.
            com.send(self.storage_data_com.open_computers[mac_addr], get_file_transfer_complete_msg('1').encode())
        return block_files

    def _handle_client_download(self, ip_addr, port, file_name, blocks, number_of_blocks, blocks_without_extra_byte):
        """
        download file from storage computers, reconstruct it amd sent it to the client
        :param ip_addr: clients' ip address
        :param file_name:
        :param blocks:
        :param number_of_blocks:
        """
        db = DB(name=os.path.join(self.fs.path, ServerLogic.DB_NAME))
        if ip_addr in self.users:
            storage_ips = [self.storage_data_com.open_computers[mac_addr] for mac_addr in blocks.values()]
            client_files_com = ServerComFT(port, self.fs, banned_ip_addresses=[], allowed_ip_addresses=[ip_addr])
            storage_files_port = self._get_port()
            storage_files_com = ServerComFT(storage_files_port, self.fs, banned_ip_addresses=[],
                                            allowed_ip_addresses=storage_ips)
            data_blocks = {}
            parity_blocks = {}
            storage_computers = {}
            for block_name, mac_addr in list(blocks.items()):  # split data and parity blocks.
                index = block_name[block_name.rfind(' '):].strip()
                if index[0] == 'D':
                    data_blocks[block_name] = mac_addr
                    storage_computers[mac_addr] = index[1:]
                else:
                    parity_blocks[block_name] = mac_addr

            file_size = db.get_size(file_name)
            file_save_size = file_size + number_of_blocks - blocks_without_extra_byte
            for block_name, mac_addr in data_blocks.items():  # ask for all data blocks
                self.storage_data_com.send(mac_addr, get_download_request_msg(block_name, '1', storage_files_port))

            file = File('temp_files' + '\\' + file_name)
            file.size = 0
            if number_of_blocks == len(data_blocks):  # if all data blocks are accessible (don't ask for parity blocks)

                block_size = file_save_size // number_of_blocks
                data_block_files = self.receive_blocks(storage_files_com, data_blocks, block_size, storage_computers)
                for index, f in sorted(data_block_files.items()):
                    data = self.fs.read(f)
                    if int(index) >= blocks_without_extra_byte:
                        data = data[1:]
                    while data is not None:
                        self.fs.write(file, data)
                        data = self.fs.read(f)  # read new data from file.
                self.fs.close_file(file)

                for f in list(data_block_files.values()):
                    self.fs.delete(f.name)

                while not ip_addr in client_files_com.open_clients.values():
                    pass
            else:
                block_size = file_save_size // number_of_blocks
                data_block_files = self.receive_blocks(storage_files_com, data_blocks, block_size, storage_computers)
                # got all data blocks, ask for parity blocks
                for block_name, mac_addr in parity_blocks.items():  # ask for all data blocks
                    self.storage_data_com.send(mac_addr, get_download_request_msg(block_name, '1', storage_files_port))

                parity_block_files = self.receive_blocks(storage_files_com, parity_blocks, block_size,
                                                         storage_computers)
                parities = self._get_parity_blocks(number_of_blocks)

                for parity in list(parities.keys()):
                    p_name = str(parity).zfill(2)
                    if p_name not in parity_block_files:
                        del parities[parity]

                while len(data_block_files) != number_of_blocks:  # go while dont have all data blocks.
                    for i in range(number_of_blocks):  # for every block needed
                        data_block = str(i).zfill(2)  # didn't receive block

                        if data_block not in data_block_files:

                            for parity, contained in parities.items():  # go over every parity block

                                if data_block in contained:  # if needed block is a part of the parity block
                                    next_parity_check = False
                                    completing_block_names = list(contained)  # list of all other blocks in parity
                                    completing_block_names.remove(data_block)
                                    # make sure that got all data blocks that are needed.
                                    for index in completing_block_names:
                                        if index not in data_block_files:
                                            next_parity_check = True
                                            break
                                    # if got all other blocks
                                    if not next_parity_check:
                                        # make file object for new data block
                                        data_block_files[data_block] = File(
                                            f'temp_files\\{file_name} D{data_block.zfill(2)}')
                                        while True:
                                            # read chunks of data from each data block in the parity and
                                            # xor with the parity to get the missing data block.
                                            blocks_data = {}
                                            for j in completing_block_names:  # read a block of data from each file
                                                read_data = self.fs.read(data_block_files[j])  # read from block file
                                                if read_data is None:
                                                    blocks_data = None
                                                    break
                                                blocks_data[j] = read_data

                                            parity_data = self.fs.read(parity_block_files[str(parity).zfill(2)])

                                            if not blocks_data:
                                                # if not using any other data block (parity data is the block data)
                                                if not completing_block_names and parity_data is not None:
                                                    self.fs.write(data_block_files[data_block], parity_data)
                                                else:
                                                    for j in contained:  # close and send all files.
                                                        self.fs.close_file(data_block_files[j])
                                                    self.fs.close_file(parity_block_files[str(parity).zfill(2)])
                                                    break

                                            else:
                                                for j in completing_block_names:
                                                    parity_data = ServerLogic._byte_xor(parity_data, blocks_data[j])
                                                # write parity to parity file
                                                self.fs.write(data_block_files[data_block], parity_data)

                for index, f in sorted(data_block_files.items()):
                    data = self.fs.read(f)
                    if int(index) >= blocks_without_extra_byte:
                        data = data[1:]
                    while data is not None:
                        self.fs.write(file, data)
                        data = self.fs.read(f)  # read new data from file.
                self.fs.close_file(file)

                for f in list(data_block_files.values()) + list(parity_block_files.values()):
                    self.fs.delete(f.name)

            client_files_com.send_file(client_addr=ip_addr, file_path=file.name)
            ip, client_answer = client_files_com.msg_q.get()
            if client_answer.decode() == '1':
                print(f'sent file to {ip_addr}')
            else:
                print(f"failed to send file to {ip_addr}")
            self.fs.delete(file.name)


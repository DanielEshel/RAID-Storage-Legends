from client.client_com import *
from client.cp import *
import queue
import threading
from client.file_manager import *
from client.inputs import *


class ClientLogic:

    def __init__(self, server_ip: str, data_port: int):
        self.server_ip = server_ip
        self.username = None
        self.files = {}
        self.files_uploading = {}
        self.can_upload = threading.Event()
        self.can_upload.set()
        self.total_storage = 0
        self.storage_used = 0
        self.connected = threading.Event()
        self.data_com = ClientCom(server_ip=server_ip, port=data_port)
        self.file_download = FS(os.path.join(os.path.join(os.environ['USERPROFILE']), 'Downloads'))
        self.fs = FS('')
        threading.Event.wait(self.data_com.got_key)
        self.connected.set()
        self.user_q = queue.Queue()
        self.logged_in = False
        threading.Event.wait(self.data_com.got_key)  # wait for data key before continuing anything.
        threading.Thread(target=self._main_logic, daemon=True).start()

    def _main_logic(self):
        """
        main logic loop for client, handle all incoming messages from server, return data to UI.
        """
        commands = {
            '00': self.handle_system_entry_reply,
            '01': self.handle_system_entry_reply,
            '02': self.set_files_data,
            '03': self.set_storage_data,
            '04': self._upload_file,
            '05': self._delete_file,
            '07': self._download_file,
            '11': self.upload_complete
        }
        while True:
            msg = self.data_com.msg_q.get()
            msg = msg.decode()
            opcode, args = unpack(msg)

            if opcode in commands:
                commands[opcode](opcode, args)  # call function by opcode.

    def upload_complete(self, opcode, args):
        """
        handle result of file upload
        :param opcode: opcode of command
        :param args: upload result and file name.
        """
        answer = args[0]
        file_name = args[1]
        if file_name in self.files_uploading:  # remove from uploading list
            if answer == '1':
                file_path = self.files_uploading[file_name]
                file_size = get_encrypted_size(self.fs.get_size(os.path.join(file_path, file_name)))
                self.files[file_name] = file_size
                self.storage_used += file_size
            del self.files_uploading[file_name]
            self.can_upload.set()
            self.user_q.put([opcode, file_name, answer])

    def _delete_file(self, opcode, args):
        """
        delete file from client's side after server's reply for deletion request.
        :param opcode: opcode of command.
        :param args: deleted file name and answer.
        """
        file_name, answer = args
        if answer == '1':  # remove file from dict if was deleted.
            if file_name in self.files:
                del (self.files[file_name])
        self.user_q.put([opcode, file_name, answer])

    def set_storage_data(self, opcode, args):
        """
        handle server's reply for a storage status request.
        :param opcode: opcode of command.
        :param args: available and used storage for user.
        :return:
        """
        total_storage, storage_used = args
        self.total_storage = int(total_storage)
        self.storage_used = int(storage_used)
        self.user_q.put([opcode])

    def set_files_data(self, opcode, args):
        """
        handle server's reply for a files data request.
        :param opcode: opcode of command.
        :param args: list of files in a string
        """
        for file in args:
            if file:
                last_space = file.rfind(' ')
                name = file[:last_space]
                size = file[last_space:]
                self.files[name] = int(size)
        self.user_q.put([opcode])

    def handle_system_entry_reply(self, opcode, args):
        """
        handle server's system entry reply (login or sign up)
        :param opcode: opcode of command.
        :param args: arguments
        """
        answer = args[0]
        if answer == '1':
            self.logged_in = True
        self.user_q.put([opcode, answer])

    def upload_files(self, file_paths: list):
        """
        upload multiple files to the server
        :param file_paths: list of files to upload
        :return: bool if uploaded successfully or not
        """
        for file in file_paths:
            threading.Event.wait(self.can_upload)
            self.upload_file(file)
        return True

    def upload_file(self, file_path: str):
        """
        send a file upload request to the server.
        :param file_path: path to file (str)
        :return: bool in uploaded successfully or not.
        """

        if os.path.isfile(file_path):
            name_div = file_path.rfind('\\')  # get starting index of file name.
            file_name = file_path[name_div+1:]
            if file_name not in self.files_uploading and file_name not in self.files:
                fs = FS(file_path[:name_div])
                size = fs.get_size(file_name)  # get file size
                file_save_size = get_encrypted_size(size)
                if file_save_size < self.total_storage - self.storage_used:
                    self.can_upload.clear()
                    self.files_uploading[file_name] = fs.path
                    msg_to_send = get_upload_request_msg(file_name, file_save_size)
                    self.data_com.send(msg_to_send)  # send message to server.
                else:
                    self.user_q.put(('04', file_name, '2'))
            else:
                self.user_q.put(('04', file_name, '0'))
        else:
            raise(FileNotFoundError(f'at ClientLogic.upload_file - could not find file: {file_path}'))

    def _upload_file(self, opcode: str, args: str):
        """
        handle server's reply to a file upload request.
        :param opcode: opcode of command
        :param args: file name, server's answer and port to upload file to.
        """
        file_name, answer, port = args
        if answer == '1':
            if port.isdigit():  # make sure port is an integer
                port = int(port)
            else:
                raise ValueError(f'at ClientLogic._main_logic - got invalid port: {port}')

            if file_name in self.files_uploading:
                fs = FS("")
                upload_com = ClientComFT(server_ip=self.server_ip, port=port, fs=fs)
                # encrypt with data key
                file_path = self.files_uploading[file_name]
                encrypted_file_path = encrypt_file(f'{file_path}\\{file_name}', self.data_com.key)
                threading.Event.wait(upload_com.connected)
                for bytes_sent in upload_com.send_file(encrypted_file_path):  # send encrypted file.
                    self.user_q.put(('10', file_name, bytes_sent))  # add to progress bar
                try:
                    upload_com.msg_q.get().decode()  # wait for confirmation message.
                except Exception as e:
                    print('at ClientLogic._upload_file - ', e)
                fs.delete(encrypted_file_path)
                upload_com.close()
        elif file_name in self.files_uploading:
            self.can_upload.set()
            del self.files_uploading[file_name]
            self.user_q.put(('11', file_name, '0'))

    def download_files(self, files: list):
        """
        download all files in list from server.
        :param files: list of file names to download.
        :return: bool if done successfully
        """
        for file in files:
            self.download_file(file)

    def download_file(self, file_name: str):
        """
        send a file download request to the server.
        :param file_name: file name (str).
        """
        if file_name in self.files:
            msg_to_send = get_download_request_msg(file_name)
            self.data_com.send(msg_to_send)
        else:
            raise ValueError(f'at ClientLogic.download_file - file not in files list: {file_name}')

    def _download_file(self, opcode: str, args: str):
        """
        download a file from the server to the path in file_download (after got confirmation).
        :param opcode: opcode of command.
        :param args: file name, server's answer, port to download file from and encryption key.
        """
        file_name, answer = args[0], args[1]
        if answer == '1':
            port, key = args[2], args[3]
            port = int(port)
            key = bytes.fromhex(key)
            fs = FS('')
            download_com = ClientComFT(server_ip=self.server_ip, port=port, fs=fs)
            threading.Event.wait(download_com.connected)
            file_size = self.files[file_name]
            file = File(f'temp_files\\{file_name}')
            while file.index < file_size:
                data = download_com.msg_q.get()
                fs.write(file, data)
                self.user_q.put(('10', file_name, len(data)))

            self.file_download.close_file(file)
            download_com.send('1')
            fs.close_file(file)
            decrypt_file(file.name, key, self.file_download.path)  # decrypt and save to downloads.
            self.user_q.put(('10', file_name, 1))
            fs.delete(file.name)
            print('downloaded file successfully')
        else:
            self.user_q.put(('12', file_name, '0'))

    def _user_info_funcs(self, username: str, password: str, f):
        """
        login, sign up, change password, ect.
        :param username: username (str).
        :param password: password (str).
        :param f: cp function of choice.
        :return: returns True if valid, 00 if invalid username and 01 if invalid password.
        """
        if valid_username(username):
            if valid_password(password):
                msg_to_send = f(username, password)  # get message
                self.data_com.send(msg_to_send)  # send message
                return True
            else:
                return '01'
        return '00'

    def login(self, username, password):
        """
        sends a login message to the server.
        :param username: username (str).
        :param password: password (str).
        :return: returns True if valid, 00 if invalid username and 01 if invalid password.
        """
        if not self.logged_in:  # make sure user is not logged in yet.
            self.username = username
            return self._user_info_funcs(username, password, get_login_msg)
        else:
            raise RuntimeError('at ClientLogic.login - user already logged in.')

    def sign_up(self, username, password):
        """
        sends a registration message to the server.
        :param username: username (str).
        :param password: password (str).
        :return: returns True if valid, 00 if invalid username and 01 if invalid password.
        """
        if not self.logged_in:  # make sure user is not logged in yet.
            self.username = username
            return self._user_info_funcs(username, password, get_registration_msg)
        else:
            raise RuntimeError('at ClientLogic.sign_up - user already logged in.')

    def change_password(self, new_password):
        """
        sends a password change message to the server.
        :param: new_password
        :return: returns True if valid, 00 if invalid username and 01 if invalid password.
        """
        if self.logged_in:  # make sure user is logged in.
            return self._user_info_funcs(self.username, new_password, get_registration_msg)
        else:
            raise RuntimeError('at ClientLogic.change_password - user not logged in.')

    def get_storage(self):
        """
        sends a storage request message to the server.
        """
        if self.logged_in:  # make sure user is logged in
            self.data_com.send(get_storage_data_msg())  # send storage data message request to server.
        else:
            raise RuntimeError('at ClientLogic.get_storage - user not logged in.')

    def get_files(self):
        """
        sends a files request message to the server.
        """
        if self.logged_in:  # make sure user is logged in
            self.data_com.send(get_files_data_msg())  # send storage data message request to server.
        else:
            raise RuntimeError('at ClientLogic.get_files - user not logged in.')

    def delete_files(self, file_names: list):
        """
        delete a list of files
        :param file_names: names of files
        """
        for file in file_names:
            self.delete_file(file)

    def delete_file(self, file_name: str):
        """
        sends a file deletion request message to the server.
        :param file_name: file to delete.
        """
        if self.logged_in:  # make sure user is logged in
            if file_name in self.files:  # make sure file is in files dict.
                self.data_com.send(get_file_deletion_msg(file_name))  # send file deletion message to server.
            else:
                raise ValueError("at ClientLogic.delete_file - file name not in client's files list.")
        else:
            raise RuntimeError('at ClientLogic.delete_file - user not logged in.')

    def log_out(self):
        """
        send log out message to server and reset user variables.
        """
        if self.logged_in:  # make sure user is logged in
            self.data_com.send(get_log_out_msg())
            self.logged_in = False
            self.username = None
            self.files = {}
            self.total_storage = 0
            self.storage_used = 0
        else:
            raise RuntimeError('at ClientLogic.log_out - user not logged in.')






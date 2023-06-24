from storage.client_com import *
from storage.scp import *
import threading
from storage.file_manager import *
import queue


class StorageLogic:

    SETTINGS = 'settings'

    def __init__(self, data_port: int, server_ip: str, allocated_storage, used_storage, storage_path: str = ''):
        self.server_ip = server_ip
        self.files = None
        self.allocated_storage = allocated_storage
        self.storage_used = used_storage
        self.fs = FS(storage_path)
        self.data_com = ClientCom(server_ip=server_ip, port=data_port)
        threading.Event.wait(self.data_com.got_key)
        self.connected = False
        threading.Thread(target=self._main_logic).start()

    def _main_logic(self):
        """
        main logic loop for client, handle all incoming messages from server, return data to UI.
        """
        self._connect()
        while True:
            data = self.data_com.msg_q.get()
            opcode, args = unpack(data.decode())

            if opcode == '06':
                answer = args[0]
                if answer == '1':
                    self.connected = True
                else:
                    exit('server disapproves connection...')

            elif opcode == '07':
                filename, answer, port = args[0], args[1], args[2]
                if port.isdigit():
                    port = int(port)
                    threading.Thread(target=self._upload_file, args=(filename, port,), daemon=True).start()

            elif opcode == '08':
                filename, file_size, port = args
                port = int(port)
                file_size = int(file_size)
                threading.Thread(target=self._download_file, args=(filename, file_size, port)).start()

            elif opcode == '10':
                file_name = args[0]
                self._delete_file(file_name)

    def _connect(self):
        """
        connect as a storage computer to the server.
        :return:
        """
        # send connection message to server.
        self.data_com.send(get_connection_msg(self.allocated_storage, self.storage_used))
        self.files = self.fs.get_files()
        print('connected to server as storage computer.')

    def _delete_file(self, file_name):
        """
        delete a file from system.
        :param file_name: name of file (str)
        """
        if file_name in self.files:
            self.fs.delete(file_name)
            self._change_storage(used=self.storage_used-self.files[file_name])
            del self.files[file_name]

    def _upload_file(self, file_name, port):
        """
        upload a file to the server.
        :param file_name: file to upload
        :param port: port to upload to
        """
        print(file_name, port)
        files_com = ClientComFT(self.server_ip, port, self.fs)
        threading.Event.wait(files_com.connected)
        if file_name in self.files:
            print('uploading file')
            files_com.send_file(file_name)  # send file to server

            server_answer = files_com.msg_q.get().decode()
            opcode, args = unpack(server_answer)
            answer = args[0]
            if answer == '1':
                files_com.close()
            else:
                raise ConnectionError(f"at StorageLogic._upload_file - server didnt get file properly."
                                      f" filename: {file_name}")
            print('file sent')
            files_com.close()

    def _change_storage(self, allocated: int = None, used: int = None):
        """
        change used and allocated storage in settings file.
        :param used: new used storage.
        :param allocated: new allocated storage.
        """
        if used is None:
            used = self.storage_used

        if allocated is None:
            allocated = self.allocated_storage

        with open("settings", 'w') as fp:
            fp.write(f'allocated storage: {allocated}\nused storage: {used}\nserver ip: {self.server_ip}\n'
                     f'storage path: {self.fs.path}')
        self.allocated_storage = allocated
        self.storage_used = used

    def _download_file(self, file_name, file_size, port):
        """
        download and save file from server.
        :param file_name: name of file
        :param file_size: size of file
        :param port: communication port
        """
        files_com = ClientComFT(self.server_ip, port, self.fs)
        threading.Event.wait(files_com.connected)
        print('opened files download com. port: ', port)
        if file_name not in self.files:
            file = File(file_name)  # open file object for file
            while file.index < file_size:
                data = files_com.msg_q.get()
                self.fs.write(file, data)
            self.fs.close_file(file)

            print("downloaded file, sent conformation!")
            files_com.send('1')  # send confirmation message to server.
            while threading.Event.is_set(files_com.connected):
                pass
            self._change_storage(used=self.storage_used+file_size)
            self.files[file_name] = file_size



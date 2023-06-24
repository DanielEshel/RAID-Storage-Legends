import random
import sqlite3
import random


class DB:
    USERS = "users"
    FILES = 'files'
    STORAGE = 'storage_computers'
    BLOCKS = 'file_blocks'

    def __init__(self, name):
        self.name = name
        self.conn = None
        self.cur = None
        self._connect()

    def _table_exists(self, name):
        """
        checks if a table exists
        :param name: name of table (str)
        :return: answer (bool)
        """
        self.cur.execute(f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{name}'")
        if self.cur.fetchone()[0] == 0:
            return False
        return True

    def _connect(self):
        """
        connects to the database. build the tables if they don't already exist.
        """
        self.conn = sqlite3.connect(self.name)
        self.cur = self.conn.cursor()
        with self.conn:
            if not self._table_exists(DB.USERS):  # init users table if doesn't exist
                self.cur.execute(f"""CREATE TABLE {DB.USERS} (
                                    username text,
                                    password text,
                                    allocated_storage integer,
                                    used_storage integer,
                                    PRIMARY KEY(username)
                                    )""")

            if not self._table_exists(DB.FILES):  # init files table if doesn't exist
                self.cur.execute(f"""CREATE TABLE {DB.FILES} (
                                    name text,
                                    blocks integer,
                                    blocks_without_extra_byte integer,
                                    size integer,
                                    encryption_key blob,
                                    PRIMARY KEY(name)
                                    )""")

            if not self._table_exists(DB.STORAGE):  # init storage computers table if doesn't exist.
                self.cur.execute(f"""CREATE TABLE {DB.STORAGE} (
                                    mac_address text,
                                    allocated_storage integer,
                                    used_storage integer,
                                    PRIMARY KEY(mac_address)
                                    )""")

            if not self._table_exists(DB.BLOCKS):  # init file_blocks table if doesn't exist.
                self.cur.execute(f"""CREATE TABLE {DB.BLOCKS} (
                                    name text, 
                                    mac_address text,
                                    PRIMARY KEY(name)
                                    )""")

    def _in_table(self, primary_key, table):
        """
        checks if a row exists in a given table.
        :param primary_key: primary key of a row
        :return: the answer (bool)
        """
        # get primary key of table
        self.cur.execute(f"SELECT l.name FROM pragma_table_info('{table}') as l WHERE l.pk = 1;")
        pk = self.cur.fetchone()[0]

        self.cur.execute(f"SELECT 1 FROM {table} WHERE {pk}=:key", {'key': primary_key})
        if self.cur.fetchone() is None:
            return False
        return True

    def user_exists(self, user):
        """
        checks if username exists in the users table.
        :param user: username (str).
        :return: bool as answer.
        """
        return self._in_table(user, DB.USERS)

    def add_user(self, user, password, allocated, used):
        """
        adds a new user to the database (if doesn't already exist).
        :param user: username (str).
        :param password: password (str).
        :param allocated: allocated storage in bytes (int).
        :param used: used storage in bytes (int).
        """
        if not self.user_exists(user):  # make sure username isn't taken
            with self.conn:
                self.cur.execute(f"INSERT INTO {DB.USERS} VALUES(:user, :password, :allocated, :used)",
                                 {'user': user, 'password': password, 'allocated': allocated, 'used': used})

    def check_password(self, user, password):
        """
        checks if the given password matches the password in the users table.
        :param user: username (str).
        :param password: password to validate (str).
        :return: the answer (bool).
        """
        self.cur.execute(f"SELECT username FROM {DB.USERS} WHERE username=:user and password=:password",
                         {'user': user, 'password': password})
        if self.cur.fetchone() is None:
            return False
        return True

    def change_password(self, user, new_password):
        """
        changes the password for the username given.
        :param user: username (str).
        :param new_password: new password (str).
        """
        if self.user_exists(user):
            with self.conn:
                self.cur.execute(f"UPDATE {DB.USERS} SET password=:password WHERE username=:user",
                                 {'user': user, 'password': new_password})

    def get_storage_data(self, user):
        """
        returns the storage used by the user.
        :param user: username (str)
        :return: allocated storage and used storage (tuple). returns None if user doesn't exist.
        """
        self.cur.execute(f"SELECT allocated_storage, used_storage FROM {DB.USERS} WHERE username=:user",
                         {'user': user})
        return self.cur.fetchone()

    def update_user_storage(self, user, new_allocated=None, new_used=None):
        """
        update the allocated or used storage in the database for a user.
        :param user: username (str)
        :param new_allocated: new allocated storage in bytes (int)
        :param new_used: used storage in bytes (int)
        """
        print(new_used, new_allocated)
        if self.user_exists(user):
            values_to_set = []
            if new_allocated is not None:
                values_to_set.append('allocated_storage=:allocated')
            if new_used is not None:
                values_to_set.append('used_storage=:used')
            values_to_set = ', '.join(values_to_set)
            with self.conn:
                self.cur.execute(f"UPDATE {DB.USERS} SET {values_to_set} WHERE username=:user", {'user': user, 'allocated': new_allocated, 'used': new_used})

    def get_storage_computers(self):
        """
        makes a dictionary of all storage computers in the storage_computers table and their values.
        :return: returns all storage computers in the storage table and their storage data (dict).
        """
        self.cur.execute(f"SELECT * FROM {DB.STORAGE}")
        storage_computer_list = self.cur.fetchall()
        storage_computers = {}
        for computer_data in storage_computer_list:  # turn the list into a dictionary
            storage_computers[computer_data[0]] = computer_data[1], computer_data[2]
        return storage_computers

    def add_storage_computer(self, mac_address, allocated, used):
        """
        adds a new storage computer to the storage_computers table.
        :param mac_address: mac address of storage computer (str)
        :param allocated: allocated storage in bytes (int)
        :param used: used storage in bytes (int)
        """
        if not self._in_table(mac_address, DB.STORAGE):  # make sure not already in the table.
            with self.conn:
                self.cur.execute(f"INSERT INTO {DB.STORAGE} VALUES(:mac, :allocated, :used)",
                                 {'mac': mac_address, 'allocated': allocated, 'used': used})

    def update_storage_data(self, mac_address, new_allocated=None, new_used=None):
        """
        changes the allocated storage or used storage of a storage computer in the storage_computers table.
        :param mac_address: mac address of storage computer (str).
        :param new_allocated: new allocated storage in bytes (int).
        :param new_used: new used storage in bytes (int).
        """
        if self._in_table(mac_address, DB.STORAGE):  # make sure mac address is in the storage computers table.
            values_to_set = []
            if new_allocated is not None:
                values_to_set.append('allocated_storage=:allocated')
            if new_used is not None:
                values_to_set.append('used_storage=:used')
            values_to_set = ', '.join(values_to_set)
            with self.conn:
                self.cur.execute(f"UPDATE {DB.STORAGE} SET {values_to_set} WHERE mac_address=:mac",
                                 {'mac': mac_address, 'allocated': new_allocated, 'used': new_used})

    def remove_storage_computer(self, mac_address):
        """
        removes a given storage computer from the storage_computers table
        :param mac_address: mac address of storage computer (str)
        """
        if self._in_table(mac_address, DB.STORAGE):
            with self.conn:
                self.cur.execute(f"DELETE FROM {DB.STORAGE} WHERE mac_address=:mac", {'mac': mac_address})
        with self.conn:
            self.cur.execute(f"DELETE FROM {DB.BLOCKS} WHERE mac_address=:mac", {'mac': mac_address})

    def file_exists(self, file_name):
        """
        checks whether a file exists in table files.
        :param file_name: name of file (str)
        :return: answer (bool)
        """
        return self._in_table(file_name, DB.FILES)

    def add_file(self, file_name, number_of_blocks, blocks_without_extra_byte, file_size,
                 encryption_key):
        """
        add a new file to the files table.
        :param file_name: name of file (str)
        :param number_of_blocks: number of blocks (int)
        :param blocks_without_extra_byte: number of blocks without an extra byte (int)
        :param file_size: size of file in bytes (int)
        :param encryption_key: symmetric encryption key for file. (str)
        """
        d = {'name': file_name,
             'blocks': number_of_blocks,
             'blocks_without_extra_byte': blocks_without_extra_byte,
             'size': file_size,
             'key': encryption_key}
        if not self.file_exists(file_name):  # make sure file doesn't already exist.
            with self.conn:
                self.cur.execute(f"INSERT INTO {DB.FILES} VALUES(:name, :blocks, :blocks_without_extra_byte,"
                                 f" :size, :key)", d)

    def get_file_blocks(self, file_name):
        """
        returns a tuple of all storage computers that are storing the file.
        :param file_name: name of file (str)
        :return: containing storage computers (tuple), returns None if file name doesn't exist.
        """
        self.cur.execute(f"SELECT name, mac_address FROM {DB.BLOCKS} WHERE name LIKE :name", {'name': f'{file_name}%'})
        return self.cur.fetchall()

    def get_number_of_blocks(self, file_name):
        """
        returns the number of blocks and the number of blocks without an extra byte that the file was split into.
        :param file_name: name of file (str)
        :return: number of blocks (int), number of blocks without extra byte(int) (tuple). None if doesn't exist.
        """
        self.cur.execute(f"SELECT blocks, blocks_without_extra_byte FROM {DB.FILES} WHERE name=:name",
                         {'name': file_name})
        return self.cur.fetchone()

    def update_file(self, file_name, number_of_blocks=None, blocks_without_extra_byte=None):
        """
        updates the values of a file in table files.
        :param file_name: name of file (str).
        :param number_of_blocks: number of blocks file was split into.
        :param blocks_without_extra_byte: number of blocks without an extra byte.
        """
        if self.file_exists(file_name):  # make sure file exists
            values_to_set = []
            if number_of_blocks:
                values_to_set.append('blocks=:blocks')
            if blocks_without_extra_byte:
                values_to_set.append('blocks_without_extra_byte=:blocks_without_extra_byte')
            values_to_set = ', '.join(values_to_set)
            with self.conn:
                self.cur.execute(f"UPDATE {DB.FILES} SET {values_to_set} WHERE name=:name",
                                 {'name': file_name, 'blocks': number_of_blocks,
                                  'blocks_without_extra_byte': blocks_without_extra_byte})

    def get_belonging_files(self, user):
        """
        returns all the files that the name starts with the username.
        :param user: username (str).
        :return: all file names and sizes (str)
        """
        print(f'getting files for: {user}')
        self.cur.execute(f"SELECT name, size FROM {DB.FILES} WHERE name LIKE :user", {'user': f'{user} % {user}'})
        files = self.cur.fetchall()
        files_dict = {}
        for file in files:
            files_dict[file[0]] = file[1]
        return files_dict

    def get_encryption_key(self, file_name):
        """
        returns the encryption key of the given file.
        :param file_name: name of file (str)
        :return: encryption key (str). None if doesn't exist.
        """
        self.cur.execute(f"SELECT encryption_key FROM {DB.FILES} WHERE name=:name", {'name': file_name})
        return self.cur.fetchone()[0]

    def get_size(self, file_name):
        """
        returns the length of the file in bytes.
        :param file_name: name of file
        :return: length of file (int). None if doesn't exist.
        """
        self.cur.execute(f"SELECT size FROM {DB.FILES} WHERE name=:name", {"name": file_name})
        res = self.cur.fetchone()
        if res is not None:
            return res[0]

    def remove_file(self, file_name):
        """
        removes a file from the files table and the blocks table.
        :param file_name: name of file (str)
        """
        if self.file_exists(file_name):
            with self.conn:
                self.cur.execute(f"DELETE FROM {DB.FILES} WHERE name=:name", {'name': file_name})
                # self.cur.execute(f"DELETE FROM {DB.BLOCKS} WHERE name LIKE :name", {'name': f'{file_name}%'})

    def get_contained_files(self, mac_address):
        """
        returns all the file block names that the storage computer is storing.
        :param mac_address: mac address of storage computer (str)
        :return: all file names (tuple). returns None if no files.
        """
        self.cur.execute(f"SELECT name FROM {DB.BLOCKS} WHERE mac_address=:mac", {'mac': mac_address})
        return self.cur.fetchall()

    def add_block(self, name, mac_address):
        """
        adds a block to the file_blocks table.
        :param name: file name (str).
        :param mac_address: mac address of storage computer containing the block (str).
        """
        if not self._in_table(name, DB.BLOCKS):  # make sure block name isn't already in the table.
            with self.conn:
                self.cur.execute(f"INSERT INTO {DB.BLOCKS} VALUES (:name, :mac)", {'name': name, 'mac': mac_address})

    def remove_block(self, name):
        """
        removes a block from the file_blocks table.
        :param name: file name (str).
        """
        if self._in_table(name, DB.BLOCKS):  # make sure block name is in table.
            with self.conn:
                self.cur.execute(f"DELETE FROM {DB.BLOCKS} WHERE name=:name", {'name': name})


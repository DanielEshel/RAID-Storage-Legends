import os


class File:
    def __init__(self, name: str):
        self.fp = None
        self.name = name
        self.index = 0
        self.size = None

    def close(self):
        if self.fp is not None:
            self.fp.close()
            self.index = 0
            self.size = None
            self.fp = None


class FS:

    MAX_READ_SIZE = 2048

    def __init__(self, path: str):
        self.path = path
        self.open_files = []

    def read(self, file: File, start: int = None, end: int = None, close=True):
        """
        read bytes from file. MAX_READ_SIZE at a time.
        :param file: File object representing file.
        :param start: starting index in file (int).
        :param end: ending index in file (int).
        :param close: flag if to close file when read data is None.
        :return: file bytes or None if EOF or end.
        """
        file_path = os.path.join(self.path, file.name)

        if os.path.isfile(file_path):

            if file.fp is None:
                file.fp = open(file_path, 'rb')
                if start is not None:
                    file.fp.seek(start)
                    file.index = start
                if end is None:
                    file.size = self.get_size(file.name)
                else:
                    file.size = end
                self.open_files.append(file)

            if file.index < file.size:
                if file.size - file.index > FS.MAX_READ_SIZE:
                    data = file.fp.read(FS.MAX_READ_SIZE)
                else:
                    data = file.fp.read(file.size-file.index)
                file.index = file.fp.tell()  # update index
                return data

            else:
                if close:
                    self.close_file(file)
                return None

        else:
            raise FileNotFoundError(f"could not find file - path: {file_path}")

    def write(self, file: File, data: bytes, end: bool = False, mode: str = 'w'):
        """
        write given data into file.
        :param file: File object representing file.
        :param data: data to write (bytes)
        :param end: if to close file after write (bool)
        :param mode: file writing mode. (str)
        """
        file_path = os.path.join(self.path, file.name)

        if file.fp is None:
            file.fp = open(file_path, f'{mode}b')
            file.size = self.get_size(file.name)
            self.open_files.append(file)

        file.fp.seek(file.index)
        file.fp.write(data)
        file.index = file.fp.tell()
        if end:
            self.close_file(file)

    def close_file(self, file: File):
        """
        closes a file and removes it from the open files list.
        :param file: file to close
        """
        if file in self.open_files:
            file.close()
            self.open_files.remove(file)

    def get_size(self, file_name: str):
        """
        get size of file.
        :param file_name: name of file. (str)
        :return: size of file (int)
        """
        file_path = os.path.join(self.path, file_name)
        return os.path.getsize(file_path)

    def delete(self, file_name: str):
        """
        delete a file.
        :param file_name: name of file. (str)
        """
        file_path = os.path.join(self.path, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)
        else:
            print(ValueError(f'at FS.delete - given path is not a file: {file_path}'))

    def get_files(self):
        """
        gets all the file names and file sizes in the path.
        :return: returns a dict of file names and lengths in bytes. (dict)
        """
        files = {}
        for file in os.listdir(self.path):  # list items in directory
            file_path = os.path.join(self.path, file)  # get path
            if os.path.isfile(file_path):  # if path is a file
                files[file] = os.path.getsize(file_path)  # get size and add to dict.
        return files


def main():
    fs = FS('E:\\computer_science\\cyber\\operating systems\\project\\code')
    print(fs.get_files())


if __name__ == '__main__':
    main()
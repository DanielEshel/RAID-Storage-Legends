from server_logic import ServerLogic
import os

if __name__ == '__main__':
    ServerLogic(files_path=f"{os.path.join(os.getcwd(), 'server_files')}")

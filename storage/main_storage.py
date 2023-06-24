import os
from storage_logic import StorageLogic


def main():
    with open("settings", 'r') as fp:
        settings = fp.read()

    # get storage status
    allocated = int([v for v in settings.split('allocated storage:')[1].split('\n') if v.strip() != ''][0])
    used = int([v for v in settings.split('used storage:')[1].split('\n') if v.strip() != ''][0])

    server_ip = [v for v in settings.split('server ip:')[1].split('\n') if v.strip() != ''][0].strip()
    storage_path = [v for v in settings.split('storage path:')[1].split('\n') if v.strip() != ''][0].strip()

    # if storage path does not exist, build it.
    if not os.path.isdir(storage_path):
        print('made dir')
        os.mkdir(storage_path)

    # server_ip = input("enter server's IP address: ")
    StorageLogic(2222, server_ip, allocated, used, storage_path)


if __name__ == '__main__':
    main()
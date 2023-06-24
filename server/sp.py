

def get_login_reply(answer_code: str):
    """
    generates a login answer message.
    :param: answer_code: 0 - invlid username/password, 1 - logged in, 2 - request denied. (str)
    :return: the message (str)
    """
    return f'00 {answer_code}'


def get_user_info_update_reply(answer_code: str):
    """
    generates a registration or password change answer message.
    :param: answer_code: 0 - username taken, 1 - registered, 2 - request denied. (str)
    :return: the message (str)
    """
    return f'01 {answer_code}'


def get_files_data_msg(files: dict):
    """
    generates a files data answer message.
    :return: the message (str)
    """
    msg_data = ';'.join([f'{name} {size}' for name, size in files.items()])
    return f'02 {msg_data}'


def get_user_storage_msg(storage_available: int, storage_used: int):
    """
    generates a user storage info request message.
    :return: the message (str)
    """
    return f'03 {storage_available};{storage_used}'


def get_upload_request_reply(file_name: str, answer_code: str, port: int = ''):
    """
    generates a file upload request answer message.
    :param: answer_code: 0 - file already exists, 1 - upload request approved, 2 - not enough space, 3 - other. (str)
    :return: the message (str)
    """
    return f'04 {file_name};{answer_code};{port}'


def get_file_deletion_request_reply(file_name: str, answer_code: str):
    """
    generates a deletion request answer message.
    :param: file_name: name of file.
    :param: answer_code: 0 - file doesn't exist, 1 - request approved.
    :return: the message (str)
    """
    return f'05 {file_name};{answer_code}'


def get_storage_connection_reply(answer_code: str):
    """
    generates storage computer connection answer message.
    :param: answer_code: 0 - request denied, 1 - request approved.
    :return: the message (str)
    """
    return f'06 {answer_code}'


def get_download_request_msg(file_name: str, answer_code: str, port: int = '', encryption_key=''):
    """
    generates a file download request reply message. 0 - file not in system, 1 - request approved, 2 - server error.
    :return: the message (str)
    """
    return f'07 {file_name};{answer_code};{port};{encryption_key}'


def get_file_upload_notice_msg(file_name: str, file_size: int, port: int):
    """
    generates a file upload notice message
    :return: the message (str)
    """
    return f'08 {file_name};{file_size};{port}'


def get_file_deletion_msg(file_name: str):
    """
    generates a file deletion message.
    :return: the message (str)
    """
    return f'10 {file_name}'


def get_file_transfer_complete_msg(answer_code, file_name=''):
    """
    generates a file transfer complete message. answer codes: 0 - transfer failed, 1 - transfer successful.
    :return: the message (str)
    """
    return f'11 {answer_code};{file_name}'


def unpack(msg: str):
    """
    unpacks a message and returns the data
    :param msg: message to unpack (str)
    :return: the opcode and arguments (tuple)
    """
    if ' ' in msg:
        first_space = msg.index(' ')
        opcode = msg[:first_space]
        data = msg[first_space+1:]
        args = data.split(';')
        return opcode, args
    else:
        return msg, ''


def main():
    files = {
        'image.txt': 12345,
        'image2.txt': 1234,
        'image3.txt': 123
    }
    print(get_files_data_msg(files))


if __name__ == "__main__":
    main()




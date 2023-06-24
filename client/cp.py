

def get_login_msg(user_name, password):
    """
    generates a login message.
    :return: the message (str)
    """
    return f'00 {user_name};{password}'


def get_registration_msg(user_name, password):
    """
    generates a registration message.
    :return: the message (str)
    """
    return f'01 {user_name};{password}'


def get_files_data_msg():
    """
    generates a files data request message.
    :return: the message (str)
    """
    return '02'


def get_storage_data_msg():
    """
    generates a user storage data request message.
    :return: the message (str)
    """
    return f'03'


def get_upload_request_msg(file_name, file_size):
    """
    generates a file upload request message.
    :return: the message (str)
    """
    return f'04 {file_name};{file_size}'


def get_download_request_msg(file_name):
    """
    generates a file download request message.
    :return: the message (str)
    """
    return f'05 {file_name}'


def get_file_deletion_msg(file_name):
    """
    generates a file deletion request message.
    :return: the message (str)
    """
    return f'06 {file_name}'


def get_log_out_msg():
    """
    generates a log out message.
    :return: the message (str)
    """
    return f'07'


def unpack(msg):
    """
    unpacks a message and returns the data
    :param msg: message to unpack (str)
    :return: the opcode and arguments (tuple)
    """
    first_space = msg.index(' ')
    opcode = msg[:first_space]
    data = msg[first_space+1:]
    args = data.split(';')
    return opcode, args


def main():
    pass


if __name__ == "__main__":
    main()




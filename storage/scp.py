
def get_connection_msg(allocated_storage, storage_used):
    """
    generates a storage computer connection message.
    :return: the message (str)
    """
    return f'00 {allocated_storage};{storage_used}'


def unpack(msg):
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
    pass


if __name__ == "__main__":
    main()




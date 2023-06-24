from pathvalidate import is_valid_filename

MAX_USERNAME_LENGTH = 20
MAX_PASSWORD_LENGTH = 20
MAX_FILENAME_LENGTH = 30


def valid_username(username: str):
    """
    check if username is legal.
    """
    return 0 < len(username) <= MAX_USERNAME_LENGTH and username.isalnum()


def valid_password(password: str):
    """
    check if password is legal.
    """
    return 0 < len(password) <= MAX_PASSWORD_LENGTH and password.isalnum()


def valid_file_name(file_name: str):
    """
    check if file name is legal.
    """
    return len(file_name) < MAX_FILENAME_LENGTH and is_valid_filename(file_name)


def main():
    print(valid_username('daniel'))


if __name__ == '__main__':
    main()
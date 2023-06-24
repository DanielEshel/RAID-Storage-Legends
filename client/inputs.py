import re

MAX_USERNAME_LENGTH = 20
MAX_PASSWORD_LENGTH = 20


def valid_username(username: str):
    return 0 < len(username) <= MAX_USERNAME_LENGTH and username.isalnum()


def valid_password(password: str):
    return 0 < len(password) <= MAX_PASSWORD_LENGTH and password.isalnum()




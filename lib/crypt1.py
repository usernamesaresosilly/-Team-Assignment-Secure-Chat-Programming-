# https://cryptography.io/en/latest/fernet/
from cryptography.fernet import Fernet


def symmetric_encrypt(key, data):
    fernet = Fernet(key)
    return fernet.encrypt(data)


def symmetric_decrypt(key, data):
    fernet = Fernet(key)
    return fernet.decrypt(data)

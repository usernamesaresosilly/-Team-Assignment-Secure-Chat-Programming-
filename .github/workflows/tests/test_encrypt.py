import pytest
from cryptography.fernet import Fernet
from lib import crypt1


def test_encryption():
    key = Fernet.generate_key()
    msg = b"This is a test message."

    crypted = crypt1.symmetric_encrypt(key, msg)
    decrypted = crypt1.symmetric_decrypt(key, crypted)
    assert decrypted == msg, "Decrypted message does not match the original message."

    print("Encryption and decryption test passed.")


if __name__ == "__main__":
    pytest.main()

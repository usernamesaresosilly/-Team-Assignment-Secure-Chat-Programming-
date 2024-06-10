# https://cryptography.io/en/latest/fernet/


from cryptography.fernet import Fernet, InvalidToken

# Shared symmetric key (should be the same across all clients and the server)
SHARED_KEY = b'DD4kcPz5QLu3Yl7Mm5WqTKbpba84eKDbrR3B9ftwmPY='


def encrypt_message(message, key=SHARED_KEY):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    # print(f"Encrypting: {message} -> {encrypted_message.decode()}")
    return encrypted_message.decode()


def decrypt_message(encrypted_message, key=SHARED_KEY):
    try:
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
        # print(f"Decrypting: {encrypted_message} -> {decrypted_message}")
        return decrypted_message
    except InvalidToken as e:
        # print(f"Invalid decryption token: {e}")
        return ''
    except Exception as e:
        # print(f"Error during decryption: {e}")
        return ''

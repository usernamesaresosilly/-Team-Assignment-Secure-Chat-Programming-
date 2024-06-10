import struct

from lib.crypt1 import decrypt_message, encrypt_message
from server.protocol import PACKETS


def send(s, message='', id=None, key=None):
    if not message:
        return

    utf = message.encode() if not isinstance(message, (bytes, bytearray)) else message

    code = PACKETS[id] if id else 0

    # Encrypt the message if it’s not a plain text notification and key is provided
    if key and id not in ["USERNAME-ACCEPT", "EXIT", "FULL", "ACCEPT"]:
        encrypted_message = encrypt_message(message, key)
        utf = encrypted_message.encode()
        print(f"Sending encrypted message: {utf}")

    payload = struct.pack(
        '>iI{}s'.format(len(utf)),
        code,
        len(utf),
        utf
    )

    s.sendall(payload)





def recv(s, msg_buffers, recv_len, msg_len, msg_ids):
    if s not in msg_buffers:
        msg_buffers[s] = b''
        recv_len[s] = 0

    try:
        msg = s.recv(1024)
    except BaseException as e:
        print(f"Error receiving data: {e}")
        del msg_buffers[s]
        del recv_len[s]
        if s in msg_len:
            del msg_len[s]
        return 'ERROR'

    if not msg:
        msg_buffers[s] = None
        msg_len[s] = 0
        return 'ERROR'

    msg_buffers[s] += msg
    recv_len[s] += len(msg)

    # Check if we have received the first 8 bytes for the header.
    if s not in msg_len and recv_len[s] >= 8:
        header = msg_buffers[s][:8]
        code, length = struct.unpack('>iI', header)
        msg_buffers[s] = msg_buffers[s][8:]  # Remove the header from the buffer
        recv_len[s] -= 8
        msg_len[s] = length
        msg_ids[s] = {v: k for k, v in PACKETS.items()}[code]
        print(f"Received header: code={code}, length={length}")

    # Check if the message is done buffering.
    if s in msg_len and len(msg_buffers[s]) >= msg_len[s]:
        print(f"Complete message received: {msg_buffers[s]}")
        return 'MSG_CMPLT'

    return 'LOADING_MSG'


def get_msg_from_queue(s, msg_buffers, recv_len, msg_len, msg_ids, symmetric_keys):
    recv_str = msg_buffers[s]
    ret_str = ''

    if recv_str:
        try:
            # Decode the raw message to string
            raw_message = recv_str.decode()
            print(f"Received raw message: {raw_message}")

            # Check for system notifications that should not be decrypted
            if raw_message.startswith("User ") or raw_message.startswith(">"):
                # Handle system notifications or mixed messages
                parts = raw_message.split(" ")
                if len(parts) > 2 and parts[-1].startswith('gAAAAAB'):  # Check if the last part is encrypted
                    plain_text = " ".join(parts[:-1])
                    encrypted_content = parts[-1]

                    # Attempt to decrypt the encrypted content
                    if s in symmetric_keys and symmetric_keys[s]:
                        print(f"Attempting to decrypt message part: {encrypted_content}")
                        decrypted_msg = decrypt_message(encrypted_content, symmetric_keys[s])
                        print(f"Decrypted message content: {decrypted_msg}")

                        if decrypted_msg:
                            ret_str = f"{plain_text} {decrypted_msg}"
                        else:
                            print(f"Decryption failed or resulted in an empty message: {decrypted_msg}")
                            ret_str = raw_message  # Fallback to the raw message if decryption fails
                    else:
                        ret_str = raw_message  # If no key, keep as is
                else:
                    # Entire message is plain text
                    ret_str = raw_message
            else:
                # For messages that are expected to be completely encrypted
                if s in symmetric_keys and symmetric_keys[s]:
                    print(f"Attempting to decrypt message: {raw_message}")
                    decrypted_msg = decrypt_message(raw_message, symmetric_keys[s])
                    print(f"Decrypted message content: {decrypted_msg}")

                    if decrypted_msg:
                        ret_str = decrypted_msg
                    else:
                        print(f"Decryption failed or resulted in an empty message: {decrypted_msg}")
                        ret_str = raw_message  # Fallback to the raw message if decryption fails
                else:
                    ret_str = raw_message  # If no key, keep as is
        except Exception as e:
            print(f"Failed to decrypt message: {e}")
            ret_str = recv_str.decode() if isinstance(recv_str, bytes) else recv_str

    del msg_buffers[s]
    del recv_len[s]
    del msg_len[s]

    id = None
    if s in msg_ids:
        id = msg_ids[s]
        del msg_ids[s]

    return id, ret_str



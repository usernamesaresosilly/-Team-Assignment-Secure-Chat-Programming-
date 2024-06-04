'''
send and recv functions implementing the chatroom protocol
'''
from lib import crypt1
import struct


from server import protocol


def send(s, message='', id=None, key=None):
    utf = message

    if not isinstance(message, (bytes, bytearray)):
        utf = message.encode()

    code = protocol.PACKETS[id]

    # Encrypt the message with the symmetric key
    if key is not None:
        utf = crypt1.symmetric_encrypt(key, utf) # Include this for encryption

    payload = struct.pack(
        '>iI{}s'.format(len(utf)),
        code,
        len(utf),
        utf
    )

    s.send(payload)


def recv(s, msg_buffers, recv_len, msg_len, msg_ids):
    if s not in msg_buffers:
        msg_buffers[s] = b''
        recv_len[s] = 0

    try:
        msg = s.recv(1)
    except BaseException:
        del msg_buffers[s]
        del recv_len[s]

        if s in msg_len:
            del msg_len[s]

        return 'LOADING_MSG'

    if not msg:
        msg_buffers[s] = None
        msg_len[s] = 0

        return 'ERROR'

    msg_buffers[s] += msg
    recv_len[s] += 1

    # Check if we have received the first 8 bytes.
    if s not in msg_len and recv_len[s] == 8:
        data = struct.unpack('>iI', msg_buffers[s])

        code = data[0]
        length = data[1]

        msg_buffers[s] = b''
        msg_len[s] = length
        msg_ids[s] = {v: k for k, v in protocol.PACKETS.items()}[code]

    # Check if the message is done buffering.
    if s in msg_len and len(msg_buffers[s]) == msg_len[s]:
        return 'MSG_CMPLT'

    return 'LOADING_MSG'


def get_msg_from_queue(
        s,
        msg_buffers,
        recv_len,
        msg_len,
        msg_ids,
        symmetric_keys):
    recv_str = msg_buffers[s]
    ret_str = ''

    if recv_str is not None:

        # Decrypt the message with the symmetric key
        if s in symmetric_keys and symmetric_keys[s]:
            recv_str = crypt1.symmetric_decrypt(symmetric_keys[s], recv_str)

        try:
            ret_str = recv_str.decode()
        except BaseException:
            ret_str = recv_str

    del msg_buffers[s]
    del recv_len[s]
    del msg_len[s]

    id = None

    if s in msg_ids:
        id = msg_ids[s]
        del msg_ids[s]

    return id, ret_str

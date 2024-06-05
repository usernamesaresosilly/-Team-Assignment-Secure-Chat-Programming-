import argparse
import socket
import select
import queue
import sys

from cryptography.fernet import Fernet

from lib import LNP


def get_args():
    '''
    Gets command line arguments.
    '''

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--port",
        metavar='p',
        dest='port',
        help="port number",
        type=int,
        default=42069
    )

    parser.add_argument(
        "--ip",
        metavar='i',
        dest='ip',
        help="IP address for client",
        default='127.0.0.1'
    )

    return parser.parse_args()


# Main method
def main():
    '''
    Uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))
    key = Fernet.generate_key()
    fernet = Fernet(key)  # TODO: Create Fernetkey
    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    symmetric_keys = {}

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    waiting_accept = True
    username = ''
    clr_txt_username = ''  # TODO:  variable to for clear text username
    username_next = False

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)

                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len, msg_ids, symmetric_keys)

                    if code_id is not None:
                        code = code_id

                if code == "MSG_CMPLT":

                    if username_next:
                        print("complete")
                        username_msg = msg
                        clr_txt_username = username_msg.split(' ')[1]  # TODO: clr_txt_username for username
                        sys.stdout.write(username_msg + '\n')
                        sys.stdout.write("> " + clr_txt_username + ": ")
                        sys.stdout.flush()
                        username_next = False

                    elif msg:
                        if clr_txt_username != '':  # TODO: Use clr_txt_username for message
                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + clr_txt_username + ": ")

                        else:
                            sys.stdout.write(msg)

                        sys.stdout.flush()

                elif code == "ACCEPT":
                    waiting_accept = False
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "USERNAME-INVALID" or code == "USERNAME-TAKEN":
                    sys.stdout.write(msg)
                    sys.stdout.flush()

                elif code == "USERNAME-ACCEPT":
                    username_next = True

                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write(msg + '\n')
                    sys.stdout.flush()
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)

            ###
            ### Process user input
            ###
            else:

                msg = sys.stdin.readline()

                if not waiting_accept:
                    msg = msg.rstrip()
                    if clr_txt_username == '':  # TODO: If username not set, send as clear text
                        LNP.send(server, msg)
                    else:
                        if msg:
                            message_queue.put(msg)
                        if not ((clr_txt_username == '') or (msg == "exit()")):
                            sys.stdout.write("> " + clr_txt_username + ": ")
                            sys.stdout.flush()

        ###
        ### Send messages to server
        ###
        for s in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

            if msg:
                if msg == "exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT")

                else:
                    encrypted_msg = fernet.encrypt(msg.encode()).decode()  # TODO: encrypt message
                    LNP.send(server, encrypted_msg)  # TODO: send encryypted message

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()


if __name__ == '__main__':
    main()

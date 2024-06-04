import argparse
import socket
import select
import queue
import sys

from cryptography.fernet import Fernet

from lib import LNP


def get_args():
    '''
    Gets command line argumnets.
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
    uses a select loop to process user and server messages. Forwards user input to the server.
    '''

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    server.connect((server_addr, port))
    key = Fernet.generate_key()
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
    username_next = False

    while server in inputs:

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:

            ###
            ### Process server messages
            ###
            if s == server:

                # This point may iterate multiple times until the message is completely read since LNP.recv, receives a few bytes at a time.
                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)

                # This will not happen until the message is switched to MSG_COMPLETE when then it is read from the
                # buffer.
                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len, msg_ids, symmetric_keys)

                    if code_id is not None:
                        code = code_id
                        # print("Message ID: " + id)

                if code == "MSG_CMPLT":

                    if username_next:
                        print("complete")
                        username_msg = msg
                        username = username_msg.split(' ')[1]
                        sys.stdout.write(username_msg + '\n')
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()
                        username_next = False

                    elif msg:
                        # If username exists, add message prompt to end of message
                        if username != '':
                            sys.stdout.write('\r' + msg + '\n')
                            sys.stdout.write("> " + username + ": ")

                        # If username doesnt exist, just write message
                        else:
                            sys.stdout.write(msg)

                        sys.stdout.flush()

                # This and any other codes can be edited in protocol.py, this way you can add new codes for new
                # states, e.g., is this a public key, CODE is PUBKEY and msg contains the key.
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
                    if msg:
                        message_queue.put(msg)
                    if not ((username == '') or (msg == "exit()")):
                        sys.stdout.write("> " + username + ": ")
                        sys.stdout.flush()

        ###
        ### Send messages to server
        ###
        for s in writable:

            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

            # if there is a message to send
            if msg:

                # if exit message, send the exit code
                if msg == "exit()":
                    outputs.remove(s)
                    LNP.send(s, '', "EXIT")

                # otherwise just send the messsage
                else:
                    LNP.send(server, msg, key=key)  # actually encrypt the key

        for s in exceptional:
            print("Disconnected: Server exception")
            inputs.remove(s)

    server.close()


if __name__ == '__main__':
    main()

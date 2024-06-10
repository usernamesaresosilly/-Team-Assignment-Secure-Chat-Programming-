import argparse
import socket
import select
import queue
import sys

from lib import LNP
from lib.crypt1 import SHARED_KEY, decrypt_message, encrypt_message


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", metavar='p', dest='port', help="port number", type=int, default=42069)
    parser.add_argument("--ip", metavar='i', dest='ip', help="IP address for client", default='127.0.0.1')
    return parser.parse_args()


def log_message(message):
    print(message)


def main():

    args = get_args()
    server_addr = args.ip
    port = args.port

    server = socket.socket()
    try:
        server.connect((server_addr, port))
        log_message(f"Connected to server at {server_addr}:{port}")
    except Exception as e:
        log_message(f"Connection failed: {e}")
        return

    msg_buffer = {}
    recv_len = {}
    msg_len = {}
    msg_ids = {}
    symmetric_keys = {server: SHARED_KEY}

    inputs = [server, sys.stdin]
    outputs = [server]
    message_queue = queue.Queue()

    # Prompt user for username
    username = input("Enter your username: ")
    LNP.send(server, username, id="USERNAME-ACCEPT")  # Send the username to the server

    print(f"> {username}: ", end="", flush=True)  # Initial prompt for the user

    while server in inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for s in readable:
            if s == server:
                code = LNP.recv(s, msg_buffer, recv_len, msg_len, msg_ids)
                if code != "LOADING_MSG":
                    code_id, msg = LNP.get_msg_from_queue(s, msg_buffer, recv_len, msg_len, msg_ids, symmetric_keys)
                    if code_id is not None:
                        code = code_id

                if code == "MSG_CMPLT":
                    if msg:
                        # Clear the current input line
                        sys.stdout.write('\r' + ' ' * (len(f"> {username}: ") + len(msg)) + '\r')

                        if msg.startswith("> "):
                            parts = msg.split(": ", 1)
                            if len(parts) == 2:
                                sender, encrypted_part = parts
                                if sender.strip() != f"> {username}":  # Ignore own messages
                                    try:
                                        decrypted_content = decrypt_message(encrypted_part.strip())
                                        display_message = f"{sender}: {decrypted_content}"
                                        sys.stdout.write(display_message + '\n')
                                    except Exception:
                                        sys.stdout.write(f"{msg} (failed to decrypt)\n")
                        else:
                            sys.stdout.write(msg + '\n')

                        # Redisplay the prompt
                        sys.stdout.write(f"> {username}: ")
                        sys.stdout.flush()

                elif code == "ACCEPT":
                    sys.stdout.write('\r' + msg + '\n')
                    sys.stdout.write(f"> {username}: ")
                    sys.stdout.flush()

                elif code == "NO_MSG" or code == "EXIT":
                    sys.stdout.write('\r' + msg + '\n')
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)
                    server.close()

            else:
                msg = sys.stdin.readline().strip()
                if username and msg:
                    encrypted_msg = encrypt_message(msg)
                    message_queue.put(encrypted_msg)
                    # Display the user's own message
                    sys.stdout.write('\r' + ' ' * (len(f"> {username}: ") + len(msg)) + '\r')
                    sys.stdout.write(f"> {username}: {msg}\n")
                    sys.stdout.write(f"> {username}: ")
                    sys.stdout.flush()

        for s in writable:
            try:
                msg = message_queue.get_nowait()
            except queue.Empty:
                msg = None

            if msg:
                LNP.send(s, msg)

        for s in exceptional:
            log_message("Disconnected: Server exception")
            inputs.remove(s)

    server.close()


if __name__ == '__main__':
    main()

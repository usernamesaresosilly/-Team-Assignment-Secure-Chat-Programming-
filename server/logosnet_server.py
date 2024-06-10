import argparse
import socket
import select
import queue
import time

from lib import LNP
from lib.crypt1 import SHARED_KEY

MAX_USR = 100
TIMEOUT = 60


def log_message(message):
    pass


def is_username(name, usernames):
    if (len(name) < 1) or (len(name) > 10) or (' ' in name):
        return "USERNAME-INVALID"

    for s in usernames:
        if name == usernames[s]:
            return "USERNAME-TAKEN"

    return "USERNAME-ACCEPT"


def is_private(msg, usernames):
    str1 = msg.split(' ')[0]
    if str1[0] == '@':
        user = str1[1:]
        for sock in usernames:
            if usernames[sock] == user:
                return user
    return None


def broadcast_queue(msg, msg_queues, exclude=[]):
    if msg and len(msg) <= 1000:
        for sock in msg_queues:
            if sock not in exclude:
                msg_queues[sock].put(msg)


def private_queue(msg, msg_queues, pvt_user, usernames):
    for sock in msg_queues:
        if usernames[sock] == pvt_user:
            msg_queues[sock].put(msg)
            return


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", metavar='p', dest='port', help="port number", type=int, default=42069)
    parser.add_argument("--ip", metavar='i', dest='ip', help="IP address for client", default='127.0.0.1')
    parser.add_argument("--debug", help="turn on debugging messages", default=True, action="store_false")
    return parser.parse_args()


def main():
    args = get_args()
    port = args.port
    ip = args.ip

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setblocking(0)
    server.bind((ip, port))
    server.listen(5)

    inputs = [server]
    outputs = []
    msg_queues = {}
    n_users = 0
    user_connect_time = {}

    msg_buffers = {}
    recv_len = {}
    msg_len = {}
    usernames = {}
    msg_ids = {}
    symmetric_keys = {server: SHARED_KEY}
    msg_id = None

    while inputs:
        users = list(user_connect_time)
        for s in users:
            if (time.time() - user_connect_time[s]) > TIMEOUT:
                LNP.send(s, '', "EXIT")
                inputs.remove(s)
                outputs.remove(s)
                n_users -= 1
                del user_connect_time[s]

        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            if s is server:
                connection, client_addr = s.accept()
                connection.setblocking(0)

                if n_users < MAX_USR:
                    LNP.send(connection, '', "ACCEPT")
                    inputs.append(connection)
                    outputs.append(connection)
                    n_users += 1
                    user_connect_time[connection] = time.time()

                    log_message(f"SERVER: new connection from {client_addr}")

                else:
                    LNP.send(connection, '', "FULL")
                    connection.close()

                    log_message(f"SERVER: connection from {client_addr} refused, server full")

            else:
                msg_status = LNP.recv(s, msg_buffers, recv_len, msg_len, msg_ids)
                if msg_id is None:
                    msg_id = msg_status

                if msg_status == "MSG_CMPLT":
                    msg_id, msg = LNP.get_msg_from_queue(s, msg_buffers, recv_len, msg_len, msg_ids, symmetric_keys)

                    if not msg:
                        continue

                    log_message(f"SERVER: received {msg} from {s.getpeername()}")

                    if s in usernames:
                        pvt_user = is_private(msg, usernames)
                        formatted_msg = f"> {usernames[s]}: {msg}"
                        if pvt_user:
                            private_queue(formatted_msg, msg_queues, pvt_user, usernames)
                        else:
                            broadcast_queue(formatted_msg, msg_queues, exclude=[s])

                    else:
                        username_status = is_username(msg, usernames)
                        LNP.send(s, '', username_status)

                        if username_status == "USERNAME-ACCEPT":
                            usernames[s] = msg
                            del user_connect_time[s]
                            msg_queues[s] = queue.Queue()
                            join_msg = f"User {usernames[s]} has joined"
                            #log_message(f"SERVER: {join_msg}")
                            broadcast_queue(join_msg, msg_queues)
                        else:
                            user_connect_time[s] = time.time()
                            msg = None

                elif msg_id == "NO_MSG" or msg_id == "EXIT":
                    log_message(f"SERVER: {msg_id}: closing connection with {s.getpeername()}")

                    outputs.remove(s)
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)
                    if s in msg_queues:
                        del msg_queues[s]

                    if s in usernames:
                        for sock in msg_queues:
                            msg_queues[sock].put(f"User {usernames[s]} has left")
                        del usernames[s]

                    if s in user_connect_time:
                        del user_connect_time[s]

                    if msg_id == "EXIT":
                        LNP.send(s, '', "EXIT")

                    n_users -= 1
                    s.close()

        for s in writable:
            if s in msg_queues:
                try:
                    next_msg = msg_queues[s].get_nowait()
                except queue.Empty:
                    next_msg = None

                if next_msg:
                    LNP.send(s, next_msg)

        for s in exceptional:
            log_message(f"SERVER: handling exceptional condition for {s.getpeername()}")

            inputs.remove(s)
            outputs.remove(s)
            del msg_queues[s]
            del usernames[s]
            s.close()


if __name__ == '__main__':
    main()

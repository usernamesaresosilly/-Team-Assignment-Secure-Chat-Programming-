import argparse
import socket
import select
import queue
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from lib import LNP

MAX_USR = 100
TIMEOUT = 60


def is_username(name, usernames):
    '''
    Returns a string code with status of username
    '''
    if (len(name) < 1) or (len(name) > 10) or (' ' in name):
        return "USERNAME-INVALID"

    for s in usernames:
        if name == usernames[s]:
            return "USERNAME-TAKEN"

    return "USERNAME-ACCEPT"


def is_private(msg, usernames):
    '''
    isPrivate returns username of recipient if the msg is private and None otherwise
    '''
    str1 = msg.split(' ')[0]

    if str1[0] == '@':
        user = str1[1:len(str1)]
        for sock in usernames:
            if usernames[sock] == user:
                return user

    return None


def broadcast_queue(msg, msg_queues, exclude=[]):
    '''
    broadcast_queue loads the message into every message queue,
    excluding sockets in the exclude array
    '''

    if msg and len(msg) <= 1000:
        for sock in msg_queues:
            if sock not in exclude:
                msg_queues[sock].put(msg)


def private_queue(msg, msg_queues, pvt_user, usernames):
    '''
    private_queue loads the message into the queue of the client with the username pvt_user
    '''
    for sock in msg_queues:
        if usernames[sock] == pvt_user:
            msg_queues[sock].put(msg)
            return


def get_args():
    '''
    get command-line arguments
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

    parser.add_argument(
        "--debug",
        help="turn on debugging messages",
        default=True,
        action="store_false"
    )

    return parser.parse_args()


def main():
    '''
    Main method. Loops forever until killed
    '''
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

    # Dictionaries containing buffered messages and message state variable
    # Key for each is a socket object
    msg_buffers = {}
    recv_len = {}
    msg_len = {}
    usernames = {}
    msg_ids = {}
    symmetric_keys = {}
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

            ###
            ### Processing server connection requests
            ###
            if s is server:

                connection, client_addr = s.accept()
                connection.setblocking(0)

                if n_users < MAX_USR:

                    LNP.send(connection, '', "ACCEPT")

                    # set up connnection variables
                    inputs.append(connection)
                    outputs.append(connection)
                    n_users += 1
                    user_connect_time[connection] = time.time()

                    if args.debug:
                        print("        SERVER: new connection from " + str(client_addr))

                else:  # >100 users
                    LNP.send(connection, '', "FULL")
                    connection.close()

                    if args.debug:
                        print("        SERVER: connection from " +
                              str(client_addr) + " refused, server full")

            ###
            ### Processing client msgs
            ###
            else:

                msg_status = LNP.recv(s, msg_buffers, recv_len, msg_len, msg_ids)
                if msg_id is None:
                    msg_id = msg_status

                if msg_status == "MSG_CMPLT":

                    msg_id, msg = LNP.get_msg_from_queue(s, msg_buffers, recv_len, msg_len, msg_ids, symmetric_keys)

                    # LEAVE THE LINE BELOW ENABLED FOR TESTING PURPOSES, DO NOT CHANGE IT EITHER
                    # IF YOU ENCRYPT OR DECRYPT msg MAKE SURE THAT WHATEVER IS PRINTED FROM THE
                    # LINE BELOW IS PLAIN TEXT
                    # Note: for the end-to-end encryption clearly you will print whatever your receive
                    print("        received " + str(msg) + " from " + str(s.getpeername()))

                    # Username exists for this client, this is a message
                    if s in usernames:
                        print("Encrypted message received: ", msg)  # TODO: Debug print statement
                        pvt_user = is_private(msg, usernames)
                        msg = "> " + usernames[s] + ": " + msg
                        if pvt_user:
                            private_queue(msg, msg_queues, pvt_user, usernames)
                        else:
                            broadcast_queue(msg, msg_queues, exclude=[s])

                    # no username yet, this message is a username
                    else:
                        print(f"Checking username: {msg}")  # TODO: Debug print statement
                        username_status = is_username(msg, usernames)
                        print(f"Username status: {username_status}")  # TODO: Debug print statement
                        LNP.send(s, '', username_status)

                        if username_status == "USERNAME-ACCEPT":
                            usernames[s] = msg
                            del user_connect_time[s]
                            msg_queues[s] = queue.Queue()
                            msg = "User " + usernames[s] + " has joined"
                            print("        SERVER: " + msg)
                            broadcast_queue(msg, msg_queues)

                        else:  # invalid username
                            user_connect_time[s] = time.time()
                            msg = None

                ###
                ### Closing connection with client
                ###
                elif msg_id == "NO_MSG" or msg_id == "EXIT":

                    if args.debug:
                        print("        SERVER: " + msg_id +
                              ": closing connection with " + str(s.getpeername()))

                    outputs.remove(s)
                    inputs.remove(s)
                    if s in writable:
                        writable.remove(s)
                    if s in msg_queues:
                        del msg_queues[s]

                    # load disconnect message into msg_queues
                    if s in usernames:
                        for sock in msg_queues:
                            msg_queues[sock].put("User " + usernames[s] + " has left")
                        del usernames[s]

                    if s in user_connect_time:
                        del user_connect_time[s]

                    # If user sent disconnect message need to send one back
                    if msg_id == "EXIT":
                        LNP.send(s, '', "EXIT")

                    n_users -= 1
                    s.close()

        # Send messages to clients
        for s in writable:

            if s in msg_queues:

                try:
                    next_msg = msg_queues[s].get_nowait()

                except queue.Empty:
                    next_msg = None

                if next_msg:
                    LNP.send(s, next_msg)

        # Remove exceptional sockets from the server
        for s in exceptional:

            if args.debug:
                print("        SERVER: handling exceptional condition for " + str(s.getpeername()))
            inputs.remove(s)
            # if s in outputs:
            outputs.remove(s)
            del msg_queues[s]
            del usernames[s]
            s.close()


if __name__ == '__main__':
    main()

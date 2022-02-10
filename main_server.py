import socket
import rsa
import random

HOST = '127.0.0.1'
PORT = 7805

SIZE = 1024
PUBLIC_KEY = "77"
PRIVATE_KEY = "11"

ANSWER_OK = '{"code" : "100", "certificate" : "12345"}'
ANSWER_FAIL = '{"code" : "400", "certificate" : ""}'

def check(text):
    return random.randint(0, 1)



def server():
    host = HOST
    port = PORT

    server_socket = socket.socket()
    server_socket.bind((host, port))

    while True:
        server_socket.listen(2)
        connection, address = server_socket.accept()
        print("Connection from: " + str(address))

    # Часть 1
        data = connection.recv(SIZE).decode('utf-8')

        print("from connected user: " + str(data))
        data = PUBLIC_KEY

        connection.send(data.encode('utf-8'))
    # Часть 2
        data = connection.recv(SIZE).decode('utf-8')
        print("from connected user: " + str(data))
        if check(data):
            data = ANSWER_OK
        else:
            data = ANSWER_FAIL
        connection.send(data.encode('utf-8'))

        connection.close()


if __name__ == '__main__':
    server()

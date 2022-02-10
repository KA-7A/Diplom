import socket

HOST = '127.0.0.1'
PORT = 7805

SIZE = 1024

MSG_1 = "KEY_REQUEST"
MSG_2 = "LOGIN DATA"

def decipher(text):

    return text

def client():
    host = HOST  # as both code is running on same pc
    port = PORT  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    cls = client_socket
    # Часть 1: Отправка первичного запроса ключа и получение ответа

    cls.send(MSG_1.encode('utf-8'))
    data = cls.recv(SIZE).decode('utf-8')
    print(data)

    # Часть 2: Отправка запроса и получение ответа

    cls.send(MSG_2.encode('utf-8'))
    data = decipher(cls.recv(SIZE).decode('utf-8'))
    print(data)

    client_socket.close()


if __name__ == '__main__':
    client()

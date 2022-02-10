import socket
import json

HOST = '127.0.0.1'
PORT = 7805

SIZE = 2048

class Client(object):
    def __init__(self):

        self.host = HOST # Хост можно получить и из имени, используя gethostbyname,
                    # но в первой итерации будем считать, что айпишник и порт
                    # нам заранее известны
        self.port = PORT

        self.client_socket = socket.socket()  # instantiate
        self.client_socket.connect((self.host, self.port))  # connect to the server

    def SendMessage(self, message):
        #TODO: Не забыть, что отправка может пройти не за раз, и в таком случае нужно повторить ещё раз
        print("Отправляем:" + message)
        self.client_socket.send(message.encode('utf-8'))

    def SendKeyRequest(self):   # Отправляем специальный запрос, в котором просим открытый ключ
        message = json.dumps({"type": -1, "details": {}})
        self.SendMessage(message)


    def GetKeyResponce(self):   # Получаем информацию об открытом ключе и номере итерации
        return self.client_socket.recv(SIZE).decode('utf-8')


    def SendEndRequest(self):   # Отправляем запрос на остановку сервера, чтобы освободить порт
        message = json.dumps({"type": -100, "details": {}})
        self.SendMessage(message)

    def __del__(self):
        self.client_socket.close()


def main():
    Client_1 = Client()
    for _ in range(5): # Просто повторим, чтобы убедиться, что всё работает
        Client_1.SendKeyRequest()
        msg = Client_1.GetKeyResponce()
        print(msg)
    Client_1.SendEndRequest()
    pass

if __name__ == '__main__':
    main()


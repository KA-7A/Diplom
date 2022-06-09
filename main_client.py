import socket
import json
import os

HOST = '127.0.0.1'
PORT = 7805

SIZE = 2048

class UserData(object):
    def __init__(self, name, password):
        self.name = name
        self.hash = hash(password)
        print(self.name, self.hash)

class Client(object):
    def __init__(self, port=PORT):

        self.host = HOST # Хост можно получить и из имени, используя gethostbyname,
                    # но в первой итерации будем считать, что айпишник и порт
                    # нам заранее известны
        self.port = port

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


    def SendStopRequest(self):   # Отправляем запрос на остановку сервера, чтобы освободить порт
        message = json.dumps({"type": -100, "details": {}})
        self.SendMessage(message)

    def SendEndRequest(self):   # Отправляем запрос на остановку сервера, чтобы освободить порт
        message = json.dumps({"type": -99, "details": {}})
        self.SendMessage(message)

    def __del__(self):
        self.client_socket.close()


def main():
    user = UserData('asdf', 'bcxv')
    return 
    try:
        Client_1 = Client()
        for _ in range(10): # Просто повторим, чтобы убедиться, что всё работает
            Client_1.SendKeyRequest()
            msg = Client_1.GetKeyResponce()
            print(msg)
        # Client_1.SendEndRequest()
        Client_1.SendStopRequest()
    except Exception as err:
        if err.args[0] == 111:
            print(err.args[1])
        else:
            print(err)

    pass

if __name__ == '__main__':
    main()


import socket
import random
import json

HOST = '127.0.0.1'
PORT = 7805

SIZE = 2048

class Server(object):
    def __init__(self):

        self.host = HOST
        self.port = PORT

        self.server_socket = socket.socket()
        self.server_socket.bind((self.host, self.port))

        while True:
            self.server_socket.listen(2)
            self.connection, self.address = self.server_socket.accept()
            print("Connection from: " + str(self.address))

            code = 0
            while not code:
                code = self.DataAnalyse(self.GetMessage())
            if code == -99:     # Сбрасываем соединение (вдруг пригодится)
                self.connection.close()
            elif code == -100:  # Завершаем работу сервера
                self.connection.close()
                self.server_socket.close()
                break

    def SendMessage(self, message):
        # TODO: Не забыть, что отправка может пройти не за раз, и в таком случае нужно повторить ещё раз
        # print("Отправляем:" + message)
        self.connection.send(message.encode('utf-8'))

    def GetMessage(self):
        return json.loads(self.connection.recv(SIZE).decode('utf-8'))

    def DataAnalyse(self, message):
        print("\n ### Получен код " + str(message["type"]) + "\n")
        if int(message["type"]) == -100:
            return -100

        elif int(message["type"]) == -99:
            return -99

        elif int(message["type"]) == -1:
            message = json.dumps({
                "type": 1,
                "details": {
                    "server_public_key": "the server's public key", # Создадим в режиме онлайн или подрузим из БД
                    "operation_number": "some number, which can identify the operation on server side" # Достанем из учетной таблицы
                }}, indent=3)
            self.SendMessage(message)
            # print("Ok!")
            return 0

    def __del__(self):
        print("Server: ended")
        self.server_socket.close()

if __name__ == '__main__':
    S = Server()

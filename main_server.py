import socket
import json

HOST = '127.0.0.1'
PORT = 7805

SIZE = 2048
operation_number = 2
public_key = "1234567"

name_1 = "ka_7a"
name_2 = "ka-7a"
passwd = hash("123")
salt   = "321"
password = hash(str(passwd) + salt)


class UserData(object):
    def __init__(self, name):
        self.name = name

        # Тут мы делаем запросы в базу данных. Сейчас я этого не делаю, потому что мне лень.
        # Но потом обязательно всё прикручу, чтобы не было никаких тут блин констант, которые я захардкодил
        self.password = password
        self.allowed = [1, 2, 10]

        # TODO: сделать норм запрос в БД на предмет поиска господина с таким именем. Если не нашлось, то not_found = True
        not_found = False
        if not_found:
            self.error_code = 1
        else:
            self.error_code = 0

class Certificate(object):
    def __init__(self, number):
        self.number = number
        self.text = "text12345"
        self.expires_date = 'some date'

        # TODO: сделать норм запрос в БД на предмет поиска сертификата с таким номером. Если не нашлось, то not_found = True
        not_found = False
        expired = False
        if not_found:
            self.error_code = 1
        elif expired:
            self.error_code = 2
        else:
            self.error_code = 0


class Server(object):
    def __init__(self, port=PORT):

        self.host = HOST
        self.port = port

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
                print("Server: Stop")
                break

    def SendMessage(self, message):
        # TODO: Не забыть, что отправка может пройти не за раз, и в таком случае нужно повторить ещё раз
        # print("Отправляем:" + message)
        self.connection.send(message.encode('utf-8'))

    def GetMessage(self):
        return json.loads(self.connection.recv(SIZE).decode('utf-8'))

    def CheckUserData(self, UserData_c, UserData_d, operation_num):
                            # UserData_c -- данные, предоставленные клиентом
                            # UserData_d -- данные, подтянутые из БД
        if hash(UserData_c[1] + salt) == UserData_d.password and UserData_c[2] == operation_num:
            return True
        else: return False

    def DataAnalyse(self, message, operation_num):
        print(" ### Получен код " + str(message["type"]))
        code = int(message["type"])
        if code == -100:
            return -100

        elif code == -99:
            return -99

        elif code == -1:
            message = json.dumps({
                "type": 1,                                  # Тип: ответ с публичным ключем и номером операции
                "details": {
                    "code": 0,                              # 0 -- успешный запрос
                    "server_public_key": public_key,        # Создадим в режиме онлайн или подрузим из БД
                    "operation_number":  operation_num   # Достанем из учетной таблицы (а пока из головы)
                }}, indent=3)
            self.SendMessage(message)
            # TODO: Сделать апдейт в БД, что у нас появилась новая операция со статусом "Отправлен публичный ключ"
            return 0
            # TODO: Запилить отправку однотипных сообщений об ошибках в отдельную функцию. Но пока мне лень.
        else:   # Если код не на выход, и не на получение информации, то делаем проверку пользователя
                # Тут выясняем, есть ли у нас вообще такой пользователь
            info = message["details"]       # Записали предоставленную пользователем информацию
            UserD = UserData(info["name"])  # Подтянули данные о пользователе с таким именем из БД
            if UserD.error_code:
                message = json.dumps({"type": 0, "details": {"code": 10,    # Не ноль -- ошибка (и её код)
                                                             "message": "User not found",
                                                             "operation_number": operation_num}})
                self.SendMessage(message)   # Отправляем сообщение с ошибкой
                #TODO: Тут надо сделать апдейт в таблице, выставить статус ошибочной логинки.
                return -99                  # И сбрасываем соединение.
            # Нет смысла продолжать в том же блоке, потому что либо мы вылетим
            # оттуда с ошибкой, либо пройдём и ветвление начнется только тут

            # Тут мы проверим, что пароли и явки совпадают. Если нет, то сообщение об ошибке и навылет.
        if not self.CheckUserData((info["name"], info["pass"], info["operation_number"]), UserD, operation_number):
            message = json.dumps({"type": 0, "details": {"code": 11,
                                                         "message": "Incorrect user data or operation_number ",
                                                         "operation_number": operation_num}})
            self.SendMessage(message)  # Отправляем сообщение с ошибкой
            # TODO: Тут надо сделать апдейт в таблице, выставить статус ошибочной логинки.
            return -99  # Сбрасываем соединение

            # Сделано это для того, чтобы по сто раз не проверять одного и того же пользователя, хотя на самом деле,
            # наверное, стоило бы.Во всяком случае, это не так сложно будет поменять: достаточно будет только добавить
            # эту проверку в начало каждого блока с каждым оператором ветвления.

        if code == -2:                      # Тип: Запрос информации о доступных ключах/сертификатах пользователя
            message = json.dumps({"type": 2, "details": {"code": "code",
                                                         "message": UserD.allowed,
                                                         "operation_number": operation_num }} )
            # TODO: Сделать апдейт в БД, что мы выдали список сертификатов
            # TODO: Сделать не просто список доступных сертификатов, а ещё и доп. инфу по ним дать.
            self.SendMessage(message)   # Отправляем сообщение с результатом
            return 0

        if code == -3:                              # Тип: Выдача пользователю сертификата с определенным номером
            Cert = Certificate(int(info["certificate_number"]))
            if Cert.error_code == 1:                # В базе не нашлось сертификата с таким номером
                message = json.dumps({"type": 0, "details": {"code": 12,
                                                             "message": "Certificate not found",
                                                             "operation_number": operation_num}})
                self.SendMessage(message)  # Отправляем сообщение с ошибкой
                # TODO: Тут надо сделать апдейт в таблице, выставить статус ошибочного номера сертификата.
                return -99  # Сбрасываем соединение
            if Cert.number not in UserD.allowed:    # У этого пользователя нет доступа к этому сертификату
                message = json.dumps({"type": 0, "details": {"code": 13,
                                                             "message": "User has no permission to this certificate",
                                                             "operation_number": operation_num}})
                self.SendMessage(message)  # Отправляем сообщение с ошибкой
                # TODO: Тут надо сделать апдейт в таблице, выставить статус отсутствующих прав у пользователя
                return -99  # Сбрасываем соединение

            if Cert.error_code == 2:
                message = json.dumps({"type": 0, "details": {"code": 14,
                                                             "message": "The certificate has expired",
                                                             "operation_number": operation_num}})
                self.SendMessage(message)  # Отправляем сообщение с ошибкой
                # TODO: Тут надо сделать апдейт в таблице, выставить статус устаревшего сертификата
                return -99  # Сбрасываем соединение

            message = json.dumps({"type": 3, "details": {"code": 0,
                                                         "message": Cert.text,
                                                         "operation_number": operation_num}})
            self.SendMessage(message)
            # TODO: Сделать апдейт в таблице, выставить статус отправленного сертификата.
            return 0
        # TODO: Написать реализацию для остальных запросов, допустимых в рамках данной архитектуры
        # TODO:!!! Написать защиту от дурацкого хакера, который попробует обмануть систему и обмануть систему защиты.


    def __del__(self):
        print("Server: ended")
        self.server_socket.close()


if __name__ == '__main__':
    S = Server()

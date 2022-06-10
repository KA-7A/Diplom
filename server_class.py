from hashlib import sha256
from mysql.connector import connect, Error
import re
import ssl
import socket
import logging
import json



class Server_to_SQL(object):
    def __init__(self):
        logging.basicConfig(filename="server.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
        pass

    def _log(self, msg):
        logging.info(msg)
        print(msg)

    def __do_request(self, request, return_code=None):
        try:
            with connect(
                    host='Тут нечего смотреть',
                    user='Ну вот правда',
                    password='Правда-правда',
                    database='Не хочу менять все пароли :с',
                    autocommit=True
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(request)
                    # self._log(request)
                    if not re.match('call', request):
                        response = str(cursor.fetchall()[0][0])
                        cursor.execute('commit')
                        return response
                    else:
                        cursor.execute('select ' + return_code)
                        code = str(cursor.fetchall()[0][0])
                        return code
        except Error as e:
            print(e)
        pass

    def __get_user_hash(self, user_name, user_hash):
        return sha256((str(user_hash) + str(self.__get_salt(user_name))).encode('utf-8')).hexdigest()

    def __get_salt(self, user_name):
        return self.__do_request("select get_salt(\'" + user_name + "\')")

    def get_secret(self, user_name, user_hash, secret_num) -> (int, str):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_secret(\'" + user_name + "\', \'" + user_hash + "\'," + str(secret_num) + ")"
        response = self.__do_request(request)
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response)

    def get_my_secrets(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_my_secrets(\'" + str(user_name) + "\', \'" + str(user_hash) + "\')"
        response = self.__do_request(request)
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response[1:-1].split(sep=", "))

        pass

    def get_my_readable_secrets(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_my_readable_secrets(\'" + str(user_name) + "\', \'" + str(user_hash) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, list(set(response[1:-1].split(sep=", "))))

    def get_contacts(self, user_1_name, user_1_hash, user_2_name):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        request = "select get_contacts(\'" + str(user_1_name) + "\', \'" + str(user_1_hash) + "\',\'" + str(
            user_2_name) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response.split(sep=", "))

    def get_logs(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_logs(\'" + str(user_name) + "\',\'" + str(user_hash) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response.split(sep="),("))

    def add_contact(self, user_name, user_hash, contact):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call add_contact(\'" + str(user_name) + "\',\'" \
                  + str(user_hash) + "\',\'" \
                  + str(contact) + "\', " \
                  + return_code + ")"
        return self.__do_request(request, return_code)

    def insert_secret(self, user_name, user_hash, secret_type, secret_secret, secret_valid_to, secret_decription):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call insert_secret(\'" \
                  + str(user_name) + "\',\'" \
                  + str(user_hash) + "\',  " \
                  + str(secret_type) + "  ,\'" \
                  + str(secret_secret) + "\',\'" \
                  + str(secret_valid_to) + "\',\'" \
                  + str(secret_decription) + "\'," \
                  + str(return_code) + ")"
        return self.__do_request(request, return_code)

    def update_secret(self, user_name, user_hash, secret_num, secret_type, secret_secret, secret_valid_to, secret_decription ):
        print("В разработке")
        return -1

    def drop_secret(self, user_name, user_hash, secret_num):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call drop_secret(\'" \
                  + str(user_name) + "\',\'" \
                  + str(user_hash) + "\',  " \
                  + str(secret_num) + ",    " \
                  + str(return_code) + ")"
        return self.__do_request(request, return_code)

    def grant_all(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call grant_all(\'" \
                  + str(user_1_name) + "\',\'" \
                  + str(user_1_hash) + "\',\'" \
                  + str(user_2_name) + "\', " \
                  + str(secret_num) + ",    " \
                  + str(return_code) + ")"
        print(request)
        return self.__do_request(request, return_code)

    def grant_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call grant_read(\'" \
                  + str(user_1_name) + "\',\'" \
                  + str(user_1_hash) + "\',\'" \
                  + str(user_2_name) + "\', " \
                  + str(secret_num) + ",    " \
                  + str(return_code) + ")"
        print(request)
        return self.__do_request(request, return_code)

    def revoke_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call revoke_read(\'" \
                  + str(user_1_name) + "\',\'" \
                  + str(user_1_hash) + "\',\'" \
                  + str(user_2_name) + "\', " \
                  + str(secret_num) + ",    " \
                  + str(return_code) + ")"
        print(request)
        return self.__do_request(request, return_code)

    def add_user(self, user_1_name, user_1_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call add_user(\'" \
                  + str(user_1_name) + "\',\'" \
                  + str(user_1_hash) + "\',\'" \
                  + str(user_2_name) + "\',\'" \
                  + str(user_2_hash) + "\'," \
                  + str(user_2_type) + ",\'" \
                  + str(user_2_salt) + "\'," \
                  + str(user_2_privileged) + ", " \
                  + str(return_code) + ")"
        return self.__do_request(request, return_code)

    def get_return_description(self, code_id):
        request = "select get_error_description(" + str(code_id) + ")"
        return self.__do_request(request)


class Server(Server_to_SQL):
    def __send_response(self, connection, d_message):
        message = json.dumps(d_message, indent=4).encode('utf-8')
        self._log("Отдаем ответ клиенту\n-----------------")
        connection.send(message)

    def __get_request(self, e_message):
        return json.loads(e_message.decode('utf-8'))

    def __init__(self):
        super().__init__()
        sock = ssl.wrap_socket(socket.socket(), 'server.key', 'server.crt', True)
        sock.bind(('localhost', 43433))
        while True:
            self._log("Ждем входящее соединение")
            sock.listen(10)

            connection, addr = sock.accept()
            connection.settimeout(10)
            self._log("Получаем запрос")
            logging.info("Получаем запрос")
            data = connection.recv(1024)
            request = data
            # while data:
            #     request += data
            #     try:
            #         data = connection.recv(1024)
            #     except socket.error:
            #         break

            d_response = {"type": 1, "details": {"code": 0, "message": ''}}
            try:
                d_request = self.__get_request(request)
                try:
                    while True:
                        request_type = d_request['type']
                        if request_type == 1:
                            act = int(self.insert_secret(d_request['details']['user_name'],
                                                         d_request['details']['user_hash'],
                                                         d_request['details']['secret_type'],
                                                         d_request['details']['secret_secret'],
                                                         d_request['details']['secret_valid_to'],
                                                         d_request['details']['secret_description']))
                            if act > 0:
                                d_response['type'] = 0
                                d_response['details']['code'] = act
                                d_response['details']['message'] = self.get_return_description(act)
                            else:
                                d_response['type'] = 1
                                d_response['details']['code'] = act
                                d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 2:
                            act = int(self.drop_secret(d_request['details']['user_name'],
                                                       d_request['details']['user_hash'],
                                                       d_request['details']['secret_num']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 3:
                            act = int(self.update_secret(d_request['details']['user_name'],
                                                         d_request['details']['user_hash'],
                                                         d_request['details']['secret_num'],
                                                         d_request['details']['secret_type'],
                                                         d_request['details']['secret_secret'],
                                                         d_request['details']['secret_valid_to'],
                                                         d_request['details']['secret_description']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 4:
                            act = int(self.grant_all(d_request['details']['user_1_name'],
                                                     d_request['details']['user_1_hash'],
                                                     d_request['details']['user_2_name'],
                                                     d_request['details']['secret_num']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 5:
                            act = int(self.grant_read(d_request['details']['user_1_name'],
                                                      d_request['details']['user_1_hash'],
                                                      d_request['details']['user_2_name'],
                                                      d_request['details']['secret_num']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 6:
                            act = int(self.revoke_read(d_request['details']['user_1_name'],
                                                       d_request['details']['user_1_hash'],
                                                       d_request['details']['user_2_name'],
                                                       d_request['details']['secret_num']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                        elif request_type == 7:
                            act = int(self.add_user(d_request['details']['user_1_name'],
                                                    d_request['details']['user_1_hash'],
                                                    d_request['details']['user_2_name'],
                                                    d_request['details']['user_2_hash'],
                                                    d_request['details']['user_2_type'],
                                                    d_request['details']['user_2_salt'],
                                                    d_request['details']['user_2_privileged']))
                            if act > 0:
                                d_response['type'] = 0
                            else:
                                d_response['type'] = 1
                            d_response['details']['code'] = act
                            d_response['details']['message'] = self.get_return_description(act)
                            pass
                        elif request_type == 8:
                            try:
                                act = self.get_secret(d_request['details']['user_name'],
                                                      d_request['details']['user_hash'],
                                                      d_request['details']['secret_num'])
                                if act[0] >= 0:
                                    d_response['type'] = 0
                                else:
                                    d_response['type'] = 1
                                d_response['details']['code'] = act[0]
                                d_response['details']['message'] = act[1]
                            except Exception as e:
                                d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                                self._log(e)
                        elif request_type == 9:
                            try:
                                act = self.get_my_secrets(d_request['details']['user_name'],
                                                          d_request['details']['user_hash'])
                                if act[0] >= 0:
                                    d_response['type'] = 0
                                else:
                                    d_response['type'] = 1
                                d_response['details']['code'] = act[0]
                                d_response['details']['message'] = act[1]
                            except Exception as e:
                                d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                                self._log(e)
                        elif request_type == 10:
                            try:
                                act = self.get_my_readable_secrets(d_request['details']['user_name'],
                                                                   d_request['details']['user_hash'])
                                if act[0] >= 0:
                                    d_response['type'] = 0
                                else:
                                    d_response['type'] = 1
                                d_response['details']['code'] = act[0]
                                d_response['details']['message'] = act[1]
                            except Exception as e:
                                d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                                self._log(e)
                        elif request_type == 11:
                            try:
                                act = self.get_contacts(d_request['details']['user_1_name'],
                                                        d_request['details']['user_1_hash'],
                                                        d_request['details']['user_2_name'])
                                if act[0] >= 0:
                                    d_response['type'] = 0
                                else:
                                    d_response['type'] = 1
                                d_response['details']['code'] = act[0]
                                d_response['details']['message'] = act[1]
                            except Exception as e:
                                d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                                self._log(e)
                        elif request_type == 12:
                            try:
                                act = self.get_logs(d_request['details']['user_name'],
                                                    d_request['details']['user_hash'])
                                if act[0] >= 0:
                                    d_response['type'] = 0
                                else:
                                    d_response['type'] = 1
                                d_response['details']['code'] = act[0]
                                d_response['details']['message'] = act[1]
                            except Exception as e:
                                d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                                self._log(e)
                        elif request_type == -99:
                            break
                        else:
                            d_response = {"type": 0, "details": {"code": 2, "message": "Incorrect code"}}
                        self.__send_response(connection, d_response)
                        data = connection.recv(1024)
                        request = data
                        d_request = self.__get_request(request)

                except:
                    d_response = {"type": 0, "details": {"code": 0, "message": "Parse error"}}
                    self.__send_response(connection, d_response)
                    continue

            except Exception as e:
                self._log("Мы не смогли ничего нормально распарсить\n-----------------")
                d_response = {"type": 0, "details": {"code": 0, "message": "Parse error"}}
                self.__send_response(connection, d_response)
                continue




if __name__ == '__main__':
    S = Server()
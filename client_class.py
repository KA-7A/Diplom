import json
import logging
import socket
import ssl
from time import sleep


class Client(object):
    def _log(self, msg):
        logging.info(msg)
        print(msg)

    def __send_request(self, d_message):
        sleep(1)
        message = json.dumps(d_message, indent=4).encode('utf-8')
        print(message.decode('utf-8'))
        self._log('Отправляем запрос серверу, код: ' + str(d_message['type']))
        self.serv.send(message)

    def __get_response(self):
        sleep(1)
        self._log('Ждём ответ от сервера')
        response = b''
        data = self.serv.recv(1024)
        #TODO: Решить случай, в котором ответ не умещается в один пакет
        response = data
        print('Что-то получили')
        return json.loads(response.decode('utf-8'))

    def __send_get(self, d_request):
        self.__send_request(d_request)
        response = self.__get_response()
        return response

    def __init__(self):
        logging.basicConfig(filename="client.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
        self.serv = ssl.wrap_socket(socket.socket())
        self.serv.connect(('127.0.0.1', 43433))
        pass

    def insert_secret(self, user_name, user_hash, secret_type, secret_secret, secret_valid_to, secret_decription ):
        d_request = {'type': 1, 'details': {'user_name': user_name,
                                            'user_hash': user_hash,
                                            'secret_type': secret_type,
                                            'secret_secret': secret_secret,
                                            'secret_valid_to': secret_valid_to,
                                            'secret_description': secret_decription}}
        return self.__send_get(d_request)

    def drop_secret(self, user_name, user_hash, secret_num):
        d_request = {'type': 2, 'details': {'user_name': user_name,
                                            'user_hash': user_hash,
                                            'secret_num': secret_num}}
        return self.__send_get(d_request)

    def update_secret(self, user_name, user_hash, secret_num, secret_type, secret_secret, secret_valid_to, secret_decription ):
        d_request = {'type': 3, 'details': {'user_name': user_name,
                                            'user_hash': user_hash,
                                            'secret_num': secret_num,
                                            'secret_type': secret_type,
                                            'secret_secret': secret_secret,
                                            'secret_valid_to': secret_valid_to,
                                            'secret_description': secret_decription}}
        return self.__send_get(d_request)

    def grant_all(self, user_1_name, user_1_hash, user_2_name, secret_num):
        d_request = {'type': 4, 'details': {'user_1_name': user_1_name,
                                            'user_1_hash': user_1_hash,
                                            'user_2_name': user_2_name,
                                            'secret_num' : secret_num}}
        return self.__send_get(d_request)

    def grant_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        d_request = {'type': 5, 'details': {'user_1_name': user_1_name,
                                            'user_1_hash': user_1_hash,
                                            'user_2_name': user_2_name,
                                            'secret_num' : secret_num}}
        return self.__send_get(d_request)

    def revoke_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        d_request = {'type': 6, 'details': {'user_1_name': user_1_name,
                                            'user_1_hash': user_1_hash,
                                            'user_2_name': user_2_name,
                                            'secret_num' : secret_num}}
        return self.__send_get(d_request)

    def add_user(self, user_1_name, user_1_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged):
        d_request = {'type': 7, 'details': {'user_1_name': user_1_name,
                                            'user_1_hash': user_1_hash,
                                            'user_2_name': user_2_name,
                                            'user_2_hash': user_2_hash,
                                            'user_2_type': user_2_type,
                                            'user_2_salt': user_2_salt,
                                            'user_2_privileged': user_2_privileged}}
        return self.__send_get(d_request)

    def get_secret(self, user_name, user_hash, secret_num):
        d_request = {'type': 8, 'details': {'user_name': user_name,
                                            'user_hash': user_hash,
                                            'secret_num': secret_num}}
        return self.__send_get(d_request)

    def get_my_secrets(self, user_name, user_hash):
        d_request = {'type': 9, 'details': {'user_name': user_name,
                                            'user_hash': user_hash}}
        return self.__send_get(d_request)

    def get_my_readable_secrets(self, user_name, user_hash):
        d_request = {'type': 10, 'details': {'user_name': user_name,
                                             'user_hash': user_hash}}
        return self.__send_get(d_request)

    def get_contacts(self, user_1_name, user_1_hash, user_2_name):
        d_request = {'type': 11, 'details': {'user_1_name': user_1_name,
                                             'user_1_hash': user_1_hash,
                                             'user_2_name': user_2_name}}
        return self.__send_get(d_request)

    def get_logs(self, user_name, user_hash):
        d_request = {'type': 12, 'details': {'user_name': user_name,
                                             'user_hash': user_hash}}
        return self.__send_get(d_request)


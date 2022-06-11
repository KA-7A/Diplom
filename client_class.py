import json
import logging
import socket
import ssl
from hashlib import sha256
from getpass import getpass
from time import sleep


class Client(object):
    def _log(self, msg):
        logging.info(msg)

    def __send_request(self, d_message):
        sleep(1)
        message = json.dumps(d_message, indent=4).encode('utf-8')
        self._log('Отправляем запрос серверу, код: ' + str(d_message['type']))
        self.serv.send(message)

    def __get_response(self):
        self._log('Ждём ответ от сервера')
        response = b''
        data = self.serv.recv(1024)
        #TODO: Решить случай, в котором ответ не умещается в один пакет
        response = data
        return json.loads(response.decode('utf-8'))

    def __send_get(self, d_request):
        self.serv = ssl.wrap_socket(socket.socket())
        self.serv.connect(('212.193.59.19', 43433))
        self.__send_request(d_request)
        response = self.__get_response()
        self.serv.close()
        return response

    def __init__(self):
        logging.basicConfig(filename="client.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
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


class Client_wrap(Client):
    def print_response(self, message):
        msg =   "*" * (len(message) + 4) + "\n" + \
                "*" + " "*len(message) + "  *\n" + \
                "* " + str(message)    + " *\n" + \
                "*" + " "*len(message) + "  *\n" + \
                "*" * (len(message) + 4)

        print(msg)


    def c_get_secret(self):
        secret_num = input("* Enter secret num -> ")
        response = self.get_secret(self.user_name, self.user_hash, secret_num)
        try:
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(response['details']['message'])
            else:
                return str(response['details']['message'])

        except Exception as e:
            return str(e)

    def c_insert_secret(self):
        i_secret          = input("* Enter secret        (str)      -> ")
        if len(i_secret) == 0: return "Incorrect input"
        i_type            = input("* Enter secret type   (int)      -> ")
        try:
            i_type = int(i_type)
            i_valid_to    = input("* Enter valid_to date (%d.%m.%Y) -> ")
            i_description = input("* Enter description   (str)      -> ")
            response = self.insert_secret(self.user_name, self.user_hash, i_type, i_secret, i_valid_to,
                                          i_description)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return "Error: " + str(e)

    def c_drop_secret(self):
        i_secret_num = input("* Enter secret num (int) ->")
        try:
            secret_num = int(i_secret_num)
            response = self.drop_secret(self.user_name, self.user_hash, secret_num)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return str(e)

    def c_update_secret(self):
        return "* В разработке "

    def c_grant_all(self):
        user_2_name = input("* Enter user to grant name (str) -> ")
        i_secret_num = input("* Enter secret number     (int) -> ")
        try:
            secret_num = int(i_secret_num)
            response = self.grant_all(self.user_name, self.user_hash, user_2_name, secret_num)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return str(e)

    def c_grant_read(self):
        user_2_name = input("* Enter user to grant name (str) -> ")
        i_secret_num = input("* Enter secret number     (int) -> ")
        try:
            secret_num = int(i_secret_num)
            response = self.grant_read(self.user_name, self.user_hash, user_2_name, secret_num)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return str(e)

    def c_revoke_read(self):
        user_2_name  = input("* Enter user to revoke name (str) -> ")
        i_secret_num = input("* Enter secret number       (int) -> ")
        try:
            secret_num = int(i_secret_num)
            response = self.revoke_read(self.user_name, self.user_hash, user_2_name, secret_num)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return str(e)

    def c_add_user(self):
        user_2_name         = input("* Enter new user name (str)        ->")
        user_2_hash         = input("* Enter new user hash (str)        ->")
        user_2_salt         = input("* Enter new user salt (str)        ->")
        user_2_type         = input("* Enter new user type (int)        ->")
        user_2_privileged   = input("* Enter new user privileged (1/0)  ->")
        try:
            user_2_type = int(user_2_type)
            user_2_privileged = int(user_2_privileged)
            response = self.add_user(self.user_name, self.user_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return e

    def c_get_my_secrets(self):
        try:
            response = self.get_my_secrets(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return e

    def c_get_my_readable_secrets(self):
        try:
            response = self.get_my_readable_secrets(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return e

    def c_get_contacts(self):
        user_2_name = input("* Enter user\'s name (str) -> ")
        try:
            response = self.get_contacts(self.user_name, self.user_hash, user_2_name)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return e

    def c_get_logs(self):
        try:
            response = self.get_logs(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return e

    def __init__(self):
        print("****************************\n"
              "*         LOGIN            *\n"
              "****************************")
        self.user_name = input  ("* Enter user name -> ")
        user_pass = getpass("* Enter password  -> ")
        self.user_hash = sha256((str(user_pass)).encode('utf-8')).hexdigest()


        super(Client_wrap, self).__init__()
        while True:
            print("****************************\n"
                  "* 1.  Get secret           *\n"
                  "* 2.  Insert secret        *\n"
                  "* 3.  Delete secret        *\n"
                  "* 4.  Grant all            *\n"
                  "* 5.  Grant read           *\n"
                  "* 6.  Revoke read          *\n"
                  "* 7.  Add user             *\n"
                  "* 8.  Get my secrets       *\n"
                  "* 9.  Get readable secrets *\n"
                  "* 10. Get contacts         *\n"
                  "* 11. Get logs             *\n"
                  "*                          *\n"
                  "* 0.  Exit                 *\n"
                  "****************************")

            i_str = input("* -> ")
            try:
                i = int(i_str)
            except:
                continue
            if i == 0:
                break
            elif i == 1:
                response = self.c_get_secret()
                self.print_response(response)
            elif i == 2:
                response = self.c_insert_secret()
                self.print_response(response)
            elif i == 3:
                response = self.c_drop_secret()
                self.print_response(response)
            elif i == 4:
                response = self.c_grant_all()
                self.print_response(response)
            elif i == 5:
                response = self.c_grant_read()
                self.print_response(response)
            elif i == 6:
                response = self.c_revoke_read()
                self.print_response(response)
            elif i == 7:
                response = self.c_add_user()
                self.print_response(response)
            elif i == 8:
                response = self.c_get_my_secrets()
                self.print_response(response)
            elif i == 9:
                response = self.c_get_my_readable_secrets()
                self.print_response(response)
            elif i == 10:
                response = self.c_get_contacts()
                self.print_response(response)
            elif i == 11:
                response = self.c_get_logs()
                self.print_response(response)
            else:
                self.print_response("* Goodbye ")
                break


if __name__ == '__main__':
    C = Client_wrap()
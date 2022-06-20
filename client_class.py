import json
import logging
import socket
import ssl
import os
from hashlib import sha256
from getpass import getpass


class Client(object):
    def _log(self, msg):
        logging.info(msg)

    def __send_request(self, d_message):
        message = json.dumps(d_message, indent=4).encode('utf-8')
        # self._log('Отправляем запрос серверу, код: ' + str(d_message['type']))
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
        if self.addr == '' or self.port == 0:
            try:
                with open('./client_config.json', 'r', encoding='utf-8') as file:
                    self.config = json.load(file)
            except Exception:
                self._log("Error: No config file or file is not JSON")
                os._exit(1)
            try:
                self.addr = self.config['server_ip']
                self.port = self.config['server_port']
            except Exception as e:
                self._log("Error: Incorrect config file!")
                os._exit(1)
        try:
            self.serv.connect((str(self.addr), int(self.port)))
            self.__send_request(d_request)
            response = self.__get_response()
            self.serv.close()
            return response
        except OSError as err:
            response = {'type': 0, 'details': {'code' : err.args[0], 'message' : 'System error'}}
            return response

    def __init__(self):
        logging.basicConfig(filename="client.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
        self.addr = ''
        self.port = 0
        pass

    def ping(self):
        response =  self.__send_get({'type': 1024})
        return response

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

    def get_users(self, user_name, user_hash):
        d_request = {'type': 13, 'details': {'user_name': user_name,
                                             'user_hash': user_hash}}
        return self.__send_get(d_request)

    def add_contact(self, user_name, user_hash, user_contact):
        d_request = {'type': 14, 'details': {'user_name': user_name,
                                             'user_hash': user_hash,
                                             'user_contact': user_contact}}
        return self.__send_get(d_request)

    def update_password(self, user_name, user_hash, user_new_hash):
        d_request = {'type': 15, 'details': {'user_name': user_name,
                                             'user_hash': user_hash,
                                             'user_new_hash': user_new_hash}}
        return self.__send_get(d_request)

    def stop_server(self, user_name, user_hash):
        d_request = {'type': -99, 'details' : {'user_name' : user_name, 'user_hash' : user_hash}}
        return self.__send_get(d_request)

class Client_wrap(Client):
    def print_response(self, message):
        space = 0
        if type(message) != type(''):
            for i in message:
                if len(str(i)) > space:
                    space = len(str(i))
        else:
            space = len(message)

        print("*" * (space + 4))
        print("*" + " " * space + "  *")
        if type(message) != type(''):
            for i in message:
                x = space - len(i)
                print("* " + str(i) + " "* x + " *")
        else:
            print("* " + message + " *")
        print("*" + " " * space + "  *")
        print("*" * (space + 4))

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
        i_secret_id = input("* Enter secret id     (int)      -> ")
        i_secret    = input("* Enter secret        (str)      -> ")
        if len(i_secret) == 0: return "Incorrect input"
        i_type      = input("* Enter secret type   (int)      -> ")
        try:
            i_type = int(i_type)
            i_secret_id = int(i_secret_id)
            i_valid_to = input("* Enter valid_to date (%d.%m.%Y) -> ")
            i_description = input("* Enter description   (str)      -> ")
            response = self.update_secret(self.user_name, self.user_hash, i_secret_id, i_type, i_secret, i_valid_to,
                                          i_description)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return str(response['details']['message'])
        except Exception as e:
            return "Error: " + str(e)

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
        user_2_hash         = sha256(getpass("* Enter new user pass (str)        ->").encode('utf-8')).hexdigest()
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
                return response['details']['message']
        except Exception as e:
            return e

    def c_get_my_readable_secrets(self):
        try:
            response = self.get_my_readable_secrets(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return response['details']['message']
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
                return response['details']['message'][0].split(sep=',')
        except Exception as e:
            return e

    def c_get_logs(self):
        try:
            response = self.get_logs(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return response['details']['message']
        except Exception as e:
            return e

    def c_get_users(self):
        try:
            response = self.get_users(self.user_name, self.user_hash)
            if response['type'] == 1:
                return "Error: " + str(response['details']['code']) + " " + str(
                    response['details']['message'])
            else:
                return response['details']['message'][0].split(',')
        except Exception as e:
            return e

    def c_add_contact(self):
        user_contact = input("* Enter the contact (str) ->")
        response = self.add_contact(self.user_name, self.user_hash, user_contact)
        return str(response['details']['message'])

    def c_update_password(self):
        user_new_hash = sha256(getpass("* Enter new user password (str) ->").encode('utf-8')).hexdigest()
        response = self.update_password(self.user_name, self.user_hash, user_new_hash)
        return str(response['details']['message'])


    def c_stop_server(self):
        response = self.stop_server(self.user_name, self.user_hash)
        return str(response['details']['message'])

    def __init__(self):
        super(Client_wrap, self).__init__()
        m_ping = self.ping()
        if m_ping['type'] == 0:
            self._log(m_ping['details']['message'])
            if m_ping['details']['code'] == 111:
                self.print_response(('Connection error', 'Connection refused'))
            else:
                self.print_response(('Connection error', 'Unknown error'))
            os._exit(1)
        print("****************************\n"
              "*         LOGIN            *\n"
              "****************************")
        self.user_name = input  ("* Enter user name -> ")
        user_pass = getpass("* Enter password  -> ")
        self.user_hash = sha256((str(user_pass)).encode('utf-8')).hexdigest()

        while True:
            print("****************************\n"
                  "* 1.  Get my secrets       *\n"
                  "* 2.  Get readable secrets *\n"
                  "*                          *\n"
                  "* 3.  Get secret           *\n"
                  "* 4.  Insert secret        *\n"
                  "* 5.  Update secret        *\n"
                  "* 6.  Delete secret        *\n"
                  "* 7.  Grant all            *\n"
                  "* 8.  Grant read           *\n"
                  "* 9.  Revoke read          *\n"
                  "*                          *\n"
                  "* 10. Get contacts         *\n"
                  "* 11. Get users            *\n"
                  "* 12. Add contact          *\n"
                  "* 13. Update password      *\n"
                  "*                          *\n"
                  "* 14. Add user             *\n"
                  "* 15. Get logs             *\n"
                  "*                          *\n"
                  "* 0.  Exit                 *\n"
                  "****************************")

            i_str = input("* -> ")
            try:
                i = int(i_str)
            except:
                continue
            if i == 0:
                self.print_response("Goodbye")
                break
            elif i == 1:
                response = self.c_get_my_secrets()
                self.print_response(response)
            elif i == 2:
                response = self.c_get_my_readable_secrets()
                self.print_response(response)
            elif i == 3:
                response = self.c_get_secret()
                self.print_response(response)
            elif i == 4:
                response = self.c_insert_secret()
                self.print_response(response)
            elif i == 5:
                response = self.c_update_secret()
                self.print_response(response)
            elif i == 6:
                response = self.c_drop_secret()
                self.print_response(response)
            elif i == 7:
                response = self.c_grant_all()
                self.print_response(response)
            elif i == 8:
                response = self.c_grant_read()
                self.print_response(response)
            elif i == 9:
                response = self.c_revoke_read()
                self.print_response(response)
            elif i == 10:
                response = self.c_get_contacts()
                self.print_response(response)
            elif i == 11:
                response = self.c_get_users()
                self.print_response(response)
            elif i == 12:
                response = self.c_add_contact()
                self.print_response(response)
            elif i == 13:
                response = self.c_update_password()
                self.print_response(response)
            elif i == 14:
                response = self.c_add_user()
                self.print_response(response)
            elif i == 15:
                response = self.c_get_logs()
                self.print_response(response)

            elif i == -9:
                response = self.c_stop_server()
                self.print_response(response)
            else:
                continue



if __name__ == '__main__':
    C = Client_wrap()
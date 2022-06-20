from hashlib import sha256
from mysql.connector import connect, Error
from getpass import getpass
import signal
import re
import ssl
import socket
import logging
import json
import os



class Server_to_SQL(object):
    def __init__(self):

        logging.basicConfig(filename="server.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")
        self.config = {}
        try:
            with open('./server_config.json', 'r', encoding='utf-8') as file:
                self.config = json.load(file)
        except Exception:
            self._log("Error: No config file or file is not JSON")
            os._exit(1)
        try:
            self.db_host = self.config['database_host']
            self.se_host = self.config['server_host']
            self.db_port = self.config['database_port']
            self.db_user = self.config['database_user_name']
            self.db_name = self.config['database_name']
            self.key_path_public = self.config['public_key_path']
            self.key_path_private = self.config['private_key_path']
        except Exception as e:
            self._log("Error: Incorrect config file!")
            os._exit(1)
        self.db_pass = getpass("* Enter database user password -> ")
        pass

    def _log(self, msg):
        logging.info(msg)
        print(msg)

    def __do_request(self, request, return_code=None):
        try:
            with connect(
                    host=self.db_host,
                    user=self.db_user,
                    password=self.db_pass,
                    database=self.db_name,
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
        request = "select get_secret(\'" + user_name + "\', \'" + u_hash + "\'," + str(secret_num) + ")"
        response = self.__do_request(request)
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response)

    def get_my_secrets(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_my_secrets(\'" + str(user_name) + "\', \'" + str(u_hash) + "\')"
        response = self.__do_request(request)
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, response[1:-1].split(sep=", "))

        pass

    def get_my_readable_secrets(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_my_readable_secrets(\'" + str(user_name) + "\', \'" + str(u_hash) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, list(set(response[1:-1].split(sep=", "))))

    def get_contacts(self, user_1_name, user_1_hash, user_2_name):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        request = "select get_contacts(\'" + str(user_1_name) + "\', \'" + str(u_hash) + "\',\'" + str(
            user_2_name) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, (response[1:-1]).split(sep=", "))

    def get_users(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_users(\'" + str(user_name) + "\', \'" + str(u_hash) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, list(set(response[1:-1].split(sep=", "))))

    def get_logs(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        request = "select get_logs(\'" + str(user_name) + "\',\'" + str(u_hash) + "\')"
        response = (self.__do_request(request))
        if re.match('Error', response):
            code = int(re.search(r'\d+', response).group())
            return (-code, response)
        else:
            return (0, (response[2:-2]).split(sep="),("))

    def add_contact(self, user_name, user_hash, contact):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call add_contact(\'" \
                  + str(user_name)  + "\',\'" \
                  + str(u_hash)     + "\',\'" \
                  + str(contact)    + "\', " \
                  + return_code     + ")"
        return self.__do_request(request, return_code)

    def insert_secret(self, user_name, user_hash, secret_type, secret_secret, secret_valid_to, secret_description):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call insert_secret(\'" \
                  + str(user_name)          + "\',\'" \
                  + str(u_hash)             + "\',  " \
                  + str(secret_type)        + "  ,\'" \
                  + str(secret_secret)      + "\',\'" \
                  + str(secret_valid_to)    + "\',\'" \
                  + str(secret_description) + "\'," \
                  + str(return_code)        + ")"
        return self.__do_request(request, return_code)

    def update_secret(self, user_name, user_hash, secret_num, secret_type, secret_secret, secret_valid_to,
                      secret_description):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call update_secret(\'" \
                  + str(user_name)          + "\',\'" \
                  + str(u_hash)             + "\',  " \
                  + str(secret_num)         + ",    " \
                  + str(secret_type)        + "  ,\'" \
                  + str(secret_secret)      + "\',\'" \
                  + str(secret_valid_to)    + "\',\'" \
                  + str(secret_description) + "\',  " \
                  + str(return_code)        + ")"
        return self.__do_request(request, return_code)

    def drop_secret(self, user_name, user_hash, secret_num):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call drop_secret(\'" \
                  + str(user_name)      + "\',\'" \
                  + str(u_hash)         + "\',  " \
                  + str(secret_num)     + ",    " \
                  + str(return_code)    + ")"
        return self.__do_request(request, return_code)

    def grant_all(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call grant_all(\'" \
                  + str(user_1_name)    + "\',\'" \
                  + str(u_hash)         + "\',\'" \
                  + str(user_2_name)    + "\',  " \
                  + str(secret_num)     + ",    " \
                  + str(return_code)    + ")"
        return self.__do_request(request, return_code)

    def grant_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call grant_read(\'" \
                  + str(user_1_name)    + "\',\'" \
                  + str(u_hash)         + "\',\'" \
                  + str(user_2_name)    + "\',  " \
                  + str(secret_num)     + ",    " \
                  + str(return_code)    + ")"
        return self.__do_request(request, return_code)

    def revoke_read(self, user_1_name, user_1_hash, user_2_name, secret_num):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call revoke_read(\'" \
                  + str(user_1_name)    + "\',\'" \
                  + str(u_hash)         + "\',\'" \
                  + str(user_2_name)    + "\',  " \
                  + str(secret_num)     + ",    " \
                  + str(return_code)    + ")"
        return self.__do_request(request, return_code)

    def add_user(self, user_1_name, user_1_hash, user_2_name, user_2_hash, user_2_type, user_2_salt, user_2_privileged):
        u_hash = self.__get_user_hash(user_1_name, user_1_hash)
        return_code = '@o_return_code'
        request = "call add_user(\'" \
                  + str(user_1_name)        + "\',\'" \
                  + str(u_hash)             + "\',\'" \
                  + str(user_2_name)        + "\',\'" \
                  + str(sha256((user_2_hash + user_2_salt).encode('utf-8')).hexdigest()) + "\'," \
                  + str(user_2_type)        + "  ,\'" \
                  + str(user_2_salt)        + "\',"   \
                  + str(user_2_privileged)  + ", "    \
                  + str(return_code)        + ")"
        return self.__do_request(request, return_code)

    def update_password(self, user_name, user_hash, user_new_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        u_new_hash = self.__get_user_hash(user_name, user_new_hash)
        return_code = '@o_return_code'
        request = "call update_password(\'" \
            + str(user_name)   + "\',\'" \
            + str(u_hash)      + "\',\'" \
            + str(u_new_hash)  + "\',  " \
            + str(return_code) + ")"
        return self.__do_request(request, return_code)

    def get_return_description(self, code_id):
        request = "select get_error_description(" + str(code_id) + ")"
        return self.__do_request(request)

    def check_privileges(self, user_name, user_hash):
        u_hash = self.__get_user_hash(user_name, user_hash)
        return_code = '@o_return_code'
        request = "call insert_secret(\'" \
                  + str(user_name)      + "\',\'" \
                  + str(u_hash)         + "\',  " \
                  + str(return_code)    + ")"
        return self.__do_request(request, return_code)


class Server(Server_to_SQL):
    def m_killall(self, sigNum, frame):
        self.connection.close()
        os.killpg(os.getgid(), signal.SIGKILL)

    def __print_long_message(self, message):
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

    def __send_response(self, connection, d_message):
        message = json.dumps(d_message, indent=4).encode('utf-8')
        self._log("Отдаем ответ клиенту\n-----------------")
        connection.send(message)
        connection.close()

    def __get_request(self, e_message):
        return json.loads(e_message.decode('utf-8'))

    def child_process(self):
        self.connection.settimeout(1)

        self._log("Получаем запрос")
        logging.info("Получаем запрос")
        data = self.connection.recv(1024)
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
                    d_response['details']['message'] = 'OK: Insert secret'
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
                try:
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
                except Exception as e:
                    d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                    self._log(e)
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
                    print(act)
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
            elif request_type == 13:
                try:
                    act = self.get_users(d_request['details']['user_name'],
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
            elif request_type == 14:
                try:
                    act = int(self.add_contact(d_request['details']['user_name'],
                                               d_request['details']['user_hash'],
                                               d_request['details']['user_contact']))
                    if act > 0:
                        d_response['type'] = 0
                    else:
                        d_response['type'] = 1
                    d_response['details']['code'] = act
                    d_response['details']['message'] = self.get_return_description(act)
                except Exception as e:
                    d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                    self._log(e)
            elif request_type == 15:
                try:
                    act = int(self.update_password(d_request['details']['user_name'],
                                                   d_request['details']['user_hash'],
                                                   d_request['details']['user_new_hash']))
                    if act > 0:
                        d_response['type'] = 0
                    else:
                        d_response['type'] = 1
                    d_response['details']['code'] = act
                    d_response['details']['message'] = self.get_return_description(act)
                except Exception as err:
                    d_response = {"type": 0, "details": {"code": 1, "message": "Error in function"}}
                    self._log(err)
            elif request_type == 1024:
                d_response = {"type" : 1}
            elif request_type == -99:
                if self.check_privileges(d_request['user_name'], d_request['user_hash']) == 1:
                    self.__print_long_message("Server is going to stop")
                    d_response['type'] = 0
                    d_response['details']['code'] = 0
                    d_response['details']['message'] = "Ok: Server will stop"
                    self.__send_response(self.connection, d_response)

                else:
                    d_response['type'] = 1
                    d_response['details']['code'] = -2
                    d_response['details']['message'] = "Error: Access denied"
                    self.__send_response(self.connection, d_response)
                    self.connection.close()
                    os._exit(0)

            else:
                d_response = {"type": 0, "details": {"code": 2, "message": "Incorrect code"}}
            self.__send_response(self.connection, d_response)
            return

        except Exception as e:
            self._log("Мы не смогли ничего нормально распарсить\n-----------------")
            d_response = {"type": 0, "details": {"code": 0, "message": "Parse error"}}
            self.__send_response(self.connection, d_response)
            return

    def __init__(self):
        signal.signal(signal.SIGTERM, self.m_killall)
        try:
            super().__init__()
            sock = ssl.wrap_socket(socket.socket(), self.key_path_private, self.key_path_public, True)
            sock.bind((self.se_host, self.db_port))
            self._log("Ждем входящее соединение")
            self.__print_long_message(("Se_Host: " + str(self.se_host),
                                       "Se_Port: " + str(self.db_port),
                                       "Db_Host: " + str(self.db_host),
                                       "Db_User: " + str(self.db_user),
                                       "Db_na: " + str(self.db_name),
                                       "Se_Priv: " + str(self.key_path_private),
                                       "se_Publ: " + str(self.key_path_public)))

            sock.listen(10)
            while True:
                try:
                    self.connection, addr = sock.accept()
                    pid = os.fork()
                    if pid == 0:
                        self.child_process()
                        os._exit(0)
                    else:
                        c_pid, status = os.waitpid(0, os.WNOHANG)

                except OSError as err:
                    continue

        except OSError as err:
            if err.args[0] == 98:
                self.__print_long_message(("Address in use", "Please, wait and try again"))
            self._log(str(err))


if __name__ == '__main__':
    Server()

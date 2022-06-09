import ssl
import socket
import logging
logging.basicConfig(filename = "proxy.log", level = logging.DEBUG, format = "%(asctime)s - %(message)s")

def log(msg):
    logging.info(msg)
    print(msg)

for _ in range(10):
    data = b'test_message'

    serv = ssl.wrap_socket(socket.socket())
    serv.connect(('127.0.0.1', 43433))
    serv.send(data)

    log("Отправляем запрос на сервер")
    serv.send(data)

    log("Получаем ответ сервера")
    resp = b''
    serv.settimeout(1)
    data = serv.recv(1024)
    while data:
        resp += data
        try:
            data = serv.recv(1024)
        except socket.error:
            break
    logging.info(resp)
    print(data)
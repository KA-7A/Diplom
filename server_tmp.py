import ssl
import socket
import logging
logging.basicConfig(filename="proxy.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")

def log(msg):
    logging.info(msg)
    print(msg)


sock = ssl.wrap_socket(socket.socket(), 'server.key', 'server.crt', True)
sock.bind(('localhost', 43433))
while True:
    log("Ждем входящее соединение")
    sock.listen(10)

    conn, addr = sock.accept()
    log("Получаем запрос")
    logging.info("Получаем запрос")
    data = conn.recv(1024)
    if data == b'STOP':
        break
    req = b''
    conn.settimeout(0.1)
    while data:
        req += data
        try:
            data = conn.recv(1024)
        except socket.error:
            break
    log(req)
    req += b'_answer'
    log("Отдаем ответ клиенту\n-----------------")

    conn.send(req)

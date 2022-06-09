import socket
import ssl
import logging
logging.basicConfig(filename="proxy.log", level=logging.DEBUG, format="%(asctime)s - %(message)s")

def log(msg):
    logging.info(msg)
    print(msg)


def stop():

    me = ssl.wrap_socket(socket.socket())
    me.connect(('localhost', 43433) )
    me.send(b'STOP')
    me.close()

stop()




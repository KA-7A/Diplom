# Этот файл немного освободит мне руки и позволит спокойно запускать тест одной
# командой в терминале, а не как я это делал раньше

import os
import main_server
import main_client
import time

PORT = 7803


def main(port):
    pid = os.fork()
    if pid == 0:
        S = main_server.Server(port)
        os._exit(os.EX_OK)

    else:
        time.sleep(0.5)
        C = main_client.Client(port)
        C.SendKeyRequest()
        print("Client: " + C.GetKeyResponce())
        while True:
            if int(input("0. - One more time\n1. - Stop server\n -> ")) == 0:
                C.SendKeyRequest()
                print("Client: " + C.GetKeyResponce())
            else:
                C.SendStopRequest()
                os._exit(os.EX_OK)


if __name__ == '__main__':
    main(PORT)

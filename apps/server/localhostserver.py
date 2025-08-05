import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import socket

current_dir = os.path.dirname(__file__)
lib_path = os.path.abspath(os.path.join(current_dir, "../../libs/pathoram_server"))
sys.path.append(lib_path)

from pathoram_server import Oram
from pathoram_server import constants

localhost = '127.0.0.1'
port = 65432

client_conn = None

def main():
    global client_conn
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((localhost, port))

    key = AESGCM.generate_key(bit_length=256)
    oram = Oram(4096, send_message, key=key)

    while True:
        client_conn, addr = s.accept()
        with conn:
            command_len_bytes = conn.recv(constants.LENGTH_PREFIX_SIZE)
            command_len = int.from_bytes(command_len_bytes, 'big')
            command = conn.recv(command_len)
            oram.process_command(command)



def send_message(message: bytes) -> None:
    global client_conn
    client_conn.sendall(message)
    print(message)

if __name__ == "__main__":
    main()


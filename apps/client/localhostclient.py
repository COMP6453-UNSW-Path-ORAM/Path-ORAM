import sys
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import socket

current_dir = os.path.dirname(__file__)
lib_path = os.path.abspath(os.path.join(current_dir, "../../libs/pathoram_client"))
sys.path.append(lib_path)

from pathoram_client import Oram

localhost = '127.0.0.1'
port = 65432

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    key = AESGCM.generate_key(bit_length=256)
    oram = Oram(2000, send_message, key=key)

def send_message(message: bytes) -> bytes:
    s.connect((localhost, port))
    s.sendall(message)
    print(message)
    response_type = s.recv(1)
    response = b""
    if response_type == b"R":
        response += s.recv(oram.levels * oram.block_size)
    print(response_type)
    return response

if __name__ == "__main__":
    main()

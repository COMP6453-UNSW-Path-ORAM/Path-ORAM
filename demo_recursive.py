import os
import queue
import sys
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

current_dir = os.path.dirname(__file__)
lib_path = os.path.abspath(os.path.join(current_dir, "libs/pathoram_client"))
sys.path.append(lib_path)
lib_path = os.path.abspath(os.path.join(current_dir, "libs/pathoram_server"))
sys.path.append(lib_path)

from pathoram_client import ADDRESS_SIZE
from pathoram_client import OramRecursive as ClientOramRecursive
from pathoram_server import Oram as ServerOram


client_message_queue: queue.Queue[bytes] = queue.Queue()
server_message_queue: queue.Queue[bytes] = queue.Queue()

stop_event = threading.Event()


def main() -> None:
    key = AESGCM.generate_key(bit_length=256)

    # start server first!
    server_oram = ServerOram(send_message_server, key=key)
    server_thread = threading.Thread(
        target=watch_for_messages_server, args=(server_oram,)
    )
    server_thread.start()

    client_oram = ClientOramRecursive(
        2047,
        send_message_read=send_message_read,
        send_message_write=send_message_write,
        send_message_init=send_message_init,
        recursive_depth=1,
        key=key,
    )
    client_oram.write_block(0, b"abcd" * 16)
    client_oram.write_block(1, b"dbac" * 16)
    print(client_oram.read_block(0))
    print(client_oram.read_block(1))
    client_oram.write_block(0, b"1234" * 16)
    print(client_oram.read_block(0))
    stop_event.set()
    server_message_queue.put(b"")
    server_thread.join()


def watch_for_messages_server(server_oram: ServerOram) -> None:
    global server_message_queue
    while not stop_event.is_set():
        command = server_message_queue.get()
        if not stop_event.is_set():
            server_oram.process_command(command)


def send_message_init(
    client_id: bytes, storage_size: int, block_size: int, blocks_per_bucket: int
) -> None:
    global server_message_queue
    global client_message_queue
    server_message_queue.put(
        client_id
        + b"I"
        + storage_size.to_bytes(ADDRESS_SIZE, byteorder="big")
        + block_size.to_bytes(ADDRESS_SIZE, byteorder="big")
        + blocks_per_bucket.to_bytes(ADDRESS_SIZE, byteorder="big")
    )
    client_message_queue.get()


def send_message_read(client_id: bytes, addr: int) -> bytes:
    global server_message_queue
    global client_message_queue
    server_message_queue.put(
        client_id + b"R" + addr.to_bytes(ADDRESS_SIZE, byteorder="big")
    )
    message = client_message_queue.get()
    return message


def send_message_write(client_id: bytes, addr: int, message: bytes) -> None:
    global server_message_queue
    global client_message_queue
    server_message_queue.put(
        client_id + b"W" + addr.to_bytes(ADDRESS_SIZE, byteorder="big") + message
    )
    message = client_message_queue.get()
    # return message


def send_message_server(message: bytes) -> None:
    client_message_queue.put(message)


if __name__ == "__main__":
    main()

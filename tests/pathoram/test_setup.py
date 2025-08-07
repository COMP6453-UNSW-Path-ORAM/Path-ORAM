import queue
import random
import threading
from typing import Optional
import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pathoram.client import ADDRESS_SIZE
from pathoram.client.constants import DEFAULT_BLOCK_SIZE
from pathoram.client.pathoram_client import ClientOram
from pathoram.server.pathoram_server import ServerOram

class TestOram:
    def setup(self, storage_size: int):
        self.storage_size = storage_size

        self.client_message_queue: queue.Queue[bytes] = queue.Queue()
        self.server_message_queue: queue.Queue[bytes] = queue.Queue()
        
        self.key: Optional[bytes] = None
        self.client_oram: Optional[ClientOram] = None
        self.server_oram: Optional[ServerOram] = None

        self.stop_event = threading.Event()
        self.server_thread: Optional[threading.Thread] = None

        self.key = AESGCM.generate_key(bit_length=256)
        send_message_read, send_message_write, send_message_init, send_message_server = create_send_functions(self)

        # start server first!
        self.server_oram = ServerOram(send_message_server, key=self.key)
        self.server_thread = threading.Thread(
            target=watch_for_messages_server, args=(self,)
        )
        self.server_thread.start()

        self.client_oram = ClientOram(
            2047,
            send_message_read=send_message_read,
            send_message_write=send_message_write,
            send_message_init=send_message_init,
            key=self.key,
        )
        
    def teardown(self):
        self.stop_event.set()
        self.server_message_queue.put(b"")
        self.server_thread.join()

def watch_for_messages_server(test_oram: TestOram) -> None:
    while not test_oram.stop_event.is_set():
        command = test_oram.server_message_queue.get()
        if not test_oram.stop_event.is_set():
            test_oram.server_oram.process_command(command)

def create_send_functions(test_oram: TestOram):
    def send_message_init(
        client_id: bytes, storage_size: int, block_size: int, blocks_per_bucket: int
    ) -> None:
        test_oram.server_message_queue.put(
            client_id
            + b"I"
            + storage_size.to_bytes(ADDRESS_SIZE, byteorder="big")
            + block_size.to_bytes(ADDRESS_SIZE, byteorder="big")
            + blocks_per_bucket.to_bytes(ADDRESS_SIZE, byteorder="big")
        )
        test_oram.client_message_queue.get()

    def send_message_read(client_id: bytes, addr: int) -> bytes:
        test_oram.server_message_queue.put(
            client_id + b"R" + addr.to_bytes(ADDRESS_SIZE, byteorder="big")
        )
        message = test_oram.client_message_queue.get()
        return message

    def send_message_write(client_id: bytes, addr: int, message: bytes) -> None:
        test_oram.server_message_queue.put(
            client_id + b"W" + addr.to_bytes(ADDRESS_SIZE, byteorder="big") + message
        )
        message = test_oram.client_message_queue.get()
        # return message
    
    def send_message_server(message: bytes) -> None:
        test_oram.client_message_queue.put(message)

    return send_message_read, send_message_write, send_message_init, send_message_server

def pad(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE):
    '''pads any data short of the block_size'''
    if len(data) > block_size: 
        return data
    return data + (DEFAULT_BLOCK_SIZE - len(data))*b'\x00'
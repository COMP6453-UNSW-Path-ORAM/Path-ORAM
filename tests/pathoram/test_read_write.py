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

@pytest.fixture(params=[127, 15, 16383, 100000], ids=["basic", "small", "big", "huge"])
def oram_instance(request):
    '''fixture that takes variable sized orams.'''
    oram = TestOram()
    oram.setup(storage_size=request.param)
    yield oram
    oram.teardown()

@pytest.fixture
def oram_instance_specific():
    '''for single size oram use.'''
    oram = TestOram()
    oram.setup(storage_size=15)
    yield oram
    oram.teardown()

def pad(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE):
    '''pads any data short of the block_size'''
    if len(data) > block_size: 
        return data
    return data + (DEFAULT_BLOCK_SIZE - len(data))*b'\x00'

def test_read_write(oram_instance):
    '''test basic single read and write case.'''
    data = pad(b"abcd")
    oram_instance.client_oram.write_block(0, data)
    result = oram_instance.client_oram.read_block(0)
    assert result == data

def test_overwrite(oram_instance):
    '''test second write overwrites content.'''
    data = pad(b"aaaaaaa")
    data2 = pad(b"bbb")
    oram_instance.client_oram.write_block(0, data)
    oram_instance.client_oram.write_block(0, data2)
    result = oram_instance.client_oram.read_block(0)
    assert result == data2

def test_multi_read(oram_instance):
    '''test multiple reads should not change data.'''
    data = pad(b"aaaaaaa")
    oram_instance.client_oram.write_block(0, data)
    result = oram_instance.client_oram.read_block(0)
    result2 = oram_instance.client_oram.read_block(0)
    result3 = oram_instance.client_oram.read_block(0)
    assert result == data
    assert result2 == data
    assert result3 == data

def test_client_read_posmap(oram_instance):
    '''
    test leaf node for block is changed after every access.
    exposes client-side position map for testing.
    '''
    data = pad(b"aaaaaaa")
    oram_instance.client_oram.write_block(0, data)
    init_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    oram_instance.client_oram.read_block(0)
    mid_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    assert init_leaf != mid_leaf
    result = oram_instance.client_oram.read_block(0)
    res_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    assert mid_leaf != res_leaf
    assert data == result

def test_multi_ops(oram_instance_specific):
    '''test handling of multiple read and write operations.'''
    data = pad(b"aaaaaaa")
    data2 = pad(b"hello world")
    data3 = pad(b"b")
    data4 = pad(b"c")
    data5 = pad(b"d")
    oram_instance_specific.client_oram.write_block(0, data)
    oram_instance_specific.client_oram.write_block(1, data2)
    result = oram_instance_specific.client_oram.read_block(0)
    oram_instance_specific.client_oram.write_block(5, data3)
    result2 = oram_instance_specific.client_oram.read_block(1)
    result3 = oram_instance_specific.client_oram.read_block(5)
    oram_instance_specific.client_oram.write_block(7, data4)
    oram_instance_specific.client_oram.write_block(0, data5)
    result4 = oram_instance_specific.client_oram.read_block(0)
    result5 = oram_instance_specific.client_oram.read_block(7)
    assert data == result
    assert data2 == result2
    assert data3 == result3
    assert data5 == result4
    assert data4 == result5

def test_nonexistent_read(oram_instance_specific):
    '''test that reading blocks without writing anything should 
       not return any actual data, instead throw error.'''
    with pytest.raises(KeyError): 
        for i in range(15):
            oram_instance_specific.client_oram.read_block(i)

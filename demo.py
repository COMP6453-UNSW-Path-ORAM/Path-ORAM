import queue
import random
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pathoram.client import ADDRESS_SIZE
from pathoram.client.pathoram_client import ClientOram
from pathoram.server.pathoram_server import ServerOram

client_message_queue: queue.Queue[bytes] = queue.Queue()
server_message_queue: queue.Queue[bytes] = queue.Queue()

stop_event = threading.Event()


def main() -> None:
    key = AESGCM.generate_key(bit_length=256)

    # start server first!
    print("starting server for demo...")
    server_oram = ServerOram(send_message_server)
    server_thread = threading.Thread(
        target=watch_for_messages_server, args=(server_oram,)
    )
    server_thread.start()

    client_oram = ClientOram(
        2047,
        send_message_read=send_message_read,
        send_message_write=send_message_write,
        send_message_init=send_message_init,
        key=key,
    )

    data = b"abcd" * 16
    client_oram.write_block(0, data)
    print(f"client wrote [ {data} ] to block [ 0 ]")

    data = b"dbac" * 16
    client_oram.write_block(1, b"dbac" * 16)
    print(f"client wrote [ {data} ] to block [ 1 ]")

    print("client read from block [ 0 ]:")
    print(client_oram.read_block(0))

    print("client read from block [ 1 ]:")
    print(client_oram.read_block(1))

    data = b"1234" * 16
    client_oram.write_block(0, b"1234" * 16)
    print(f"client wrote [ {data} ] to block [ 0 ]")

    print("client read from block [ 0 ]:")
    print(client_oram.read_block(0))

    print("stress testing...")
    A = [b"0" * 64 for _ in range(2047)]
    for i in range(2047):
        client_oram.write_block(i, A[i])
    for _ in range(1000):
        i = random.randint(0, 2046)
        if random.choice("RW") == "R":
            assert A[i] == client_oram.read_block(i)
        else:
            d = random.randbytes(64)
            A[i] = d
            client_oram.write_block(i, d)
    print("demo finished. stopping server...")
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

import secrets
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import constants


class OramPerClient:
    """This class is intended to be used in the following simple loop
    while True:
        command = wait_for_command()
        Oram.process_command(command)
    """

    def __init__(
        self,
        storage_size: int,
        send_message: Callable[[bytes], None],
        key: bytes,
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
    ):
        # The binary tree is an array in memory
        # Such that self.tree[0] is the root node
        # and self.tree[1] and self.tree[2] are the left and right children.
        # Then the indices 3 through 6 inclusive are the 4 children on the 3rd level
        # The parent of a node with index i is (i-1) // 2
        # The left child of a node with index i is 2*i+1
        # The right child of a node with index i is 2*i+2
        self.tree: list[list[bytes]] = []

        self.storage_size: int = storage_size

        self.aes = AESGCM(key)

        self.send_message = send_message

        self.blocks_per_bucket = blocks_per_bucket

        self.levels: int = self.storage_size.bit_length()

        # The server starts out full of random encryptions of dummy blocks
        dummy_address: bytes = (256**constants.ADDRESS_SIZE - 1).to_bytes(
            constants.ADDRESS_SIZE, byteorder="big"
        )
        dummy_block: bytes = b"\0" * block_size
        for i in range(self.storage_size):
            self.tree.append([])
            for _ in range(self.blocks_per_bucket):
                nonce: bytes = secrets.token_bytes(12)
                encrypted_block = self.aes.encrypt(
                    nonce, dummy_address + dummy_block, associated_data=None
                )
                self.tree[i].append(nonce + encrypted_block)

    def process_command(self, command: bytes) -> None:
        if command[0:1] == b"R":
            self.send_message(
                b"R" + self._read_path(int.from_bytes(command[1:], byteorder="big"))
            )
        elif command[0:1] == b"W":
            self._process_write_command(command[1:])
            self.send_message(b"ok")
        else:
            self.send_message(b"E")
            raise ValueError(
                "Commands must start with 'R' or 'W'. This command starts with "
                + str(command[0:1])
            )

    # Reading a path empties that path, because a read is always followed by a write
    # Which fills the path up again
    def _read_path(self, leaf_node: int) -> bytes:
        # Adjust leaf node from measuring from the left on the leaf level
        # to measuring including all levels
        leaf_node += self.storage_size // 2
        blocks: list[bytes] = []
        current_node = leaf_node
        for i in range(self.levels - 1, -1, -1):
            bucket = self.tree[current_node]
            for block in bucket:
                blocks.append(block)
            self.tree[current_node] = []
            # Get the parent of the current node
            current_node = (current_node - 1) // 2
        return b"".join(blocks)

    # A series of these write commands should follow a read
    # The path should be empty after the read, and slowly filled by the write commands
    def _process_write_command(self, command: bytes) -> None:
        leaf_node_bytes = command[0 : constants.ADDRESS_SIZE]
        level_bytes = command[
            constants.ADDRESS_SIZE : constants.ADDRESS_SIZE + constants.LEVEL_SIZE
        ]
        leaf_node = int.from_bytes(leaf_node_bytes, byteorder="big")
        level = int.from_bytes(level_bytes, byteorder="big")
        block = command[constants.ADDRESS_SIZE + constants.LEVEL_SIZE :]
        # In order to get to the right node, start from the leaf node
        # Which is at position leaf_node+self.storage_size // 2
        # Then go to the parent however many times it takes
        # Which is self.levels - level - 1
        node_index = leaf_node + self.storage_size // 2
        for _ in range(self.levels - level - 1):
            node_index = (node_index - 1) // 2
        # The client must not write too many blocks to one bucket
        if len(self.tree[node_index]) >= self.blocks_per_bucket:
            raise IndexError("Bucket overflowed")
        self.tree[node_index].append(block)


class Oram:
    def __init__(
        self,
        send_message: Callable[[bytes], None],
        key: bytes,
    ):
        self.send_message = send_message
        self.key = key
        self.storagePerClient: dict[bytes, OramPerClient] = {}

    def process_command(self, command: bytes) -> None:
        client_id, command = command[:16], command[16:]
        # print(client_id, command)
        if command[0:1] == b"I":
            command = command[1:]
            storage_size = int.from_bytes(
                command[: constants.ADDRESS_SIZE], byteorder="big"
            )
            block_size = int.from_bytes(
                command[constants.ADDRESS_SIZE : constants.ADDRESS_SIZE * 2],
                byteorder="big",
            )
            blocks_per_bucket = int.from_bytes(
                command[constants.ADDRESS_SIZE * 2 : constants.ADDRESS_SIZE * 3],
                byteorder="big",
            )
            self.storagePerClient[client_id] = OramPerClient(
                storage_size=storage_size,
                send_message=self.send_message,
                key=self.key,
                block_size=block_size,
                blocks_per_bucket=blocks_per_bucket,
            )
            self.send_message(b"ok")
        else:
            self.storagePerClient[client_id].process_command(command)

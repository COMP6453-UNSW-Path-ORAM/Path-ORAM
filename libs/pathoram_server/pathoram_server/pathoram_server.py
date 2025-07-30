import secrets
from collections.abc import Callable
from typing import Optional

import constants
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Bucket = list[bytes]


# This class is intended to be used in the following simple loop
# while True:
#     command = wait_for_command()
#     Oram.process_command(command)
class Oram:

    def __init__(
        self,
        storage_size: int,
        send_message: Callable[[bytes], None],
        key: bytes,
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
        position_map: Optional[list[int]] = None,
        stash: Optional[dict[int, bytes]] = None,
    ):
        # The binary tree is an array in memory
        # Such that self.tree[0] is the root node
        # and self.tree[1] and self.tree[2] are the left and right children.
        # Then the indices 3 through 6 inclusive are the 4 children on the 3rd level
        # The parent of a node with index i is (i-1) // 2
        # The left child of a node with index i is 2*i+1
        # The right child of a node with index i is 2*i+2
        self.tree: list[Bucket] = []

        # TODO: make this the next highest power of 2 like in the client
        self.storage_size = storage_size

        self.aes = AESGCM(key)

        self.send_message = send_message

        self.storage_size = storage_size

        self.blocks_per_bucket = blocks_per_bucket

        self.levels: int = self.storage_size.bit_length() - 1

        # The server starts out full of random encryptions of dummy blocks
        dummy_address: bytes = (storage_size - 1).to_bytes(
            constants.ADDRESS_SIZE, byteorder="big"
        )
        dummy_block: bytes = b"\0" * block_size
        for _ in range(self.storage_size):
            nonce: bytes = secrets.token_bytes(12)
            encrypted_block = self.aes.encrypt(
                nonce, dummy_address + dummy_block, associated_data=None
            )
            self.tree.append(nonce + encrypted_block)

    def process_command(self, command: bytes) -> None:
        if command[0:1] == b"R":
            self.send_message(
                self._read_path(int.from_bytes(command[1:], byteorder="big"))
            )
        elif command[1:2] == b"W":
            self._process_write_command(command[1:])
        else:
            raise ValueError("Commands must start with 'R' or 'W'")

    # Reading a path empties that path, because a read is always followed by a write
    # Which fills the path up again
    def _read_path(self, leaf_node: int) -> bytes:
        blocks: list[bytes] = []
        for i in range(leaf_node.bit_length(), -1, -1):
            bucket = self.tree[leaf_node >> i]
            for block in bucket:
                blocks.append(block)
            self.tree[leaf_node >> i] = []
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
        # Which is self.levels - level
        node_index = (leaf_node + self.storage_size // 2) // (
            2 ** (self.levels - level)
        )
        # The client must not write too many blocks to one bucket
        if len(self.tree[node_index]) >= self.blocks_per_bucket:
            raise IndexError("Bucket overflowed")
        self.tree[node_index].append(block)

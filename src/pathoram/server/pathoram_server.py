import secrets
from typing import Callable

from . import constants


class ServerOramPerClient:
    """
    This class is intended to be used in the following simple loop:
    while True:
        command = wait_for_command()
        Oram.process_command(command)

    The class processes commands send by the client to read or write data.
    The class mainly consists of a complete binary tree where each node (bucket) contains multiple blocks.
    Implementation details for this are documented in the __init__ method.
    """

    def __init__(
        self,
        storage_size: int,
        send_message: Callable[[bytes], None],
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
    ):
        """
        This method initialises a new server ORAM, to pair with a client instance.
        It stores data in a binary tree.
        This binary tree is backed by an array in memory
        Such that self.tree[0] is the root node
        and self.tree[1] and self.tree[2] are the left and right children.
        Then the indices 3 through 6 inclusive are the 4 children on the 3rd level
        The parent of a node with index i is (i-1) // 2
        The left child of a node with index i is 2*i+1
        The right child of a node with index i is 2*i+2
        """

        self.storage_size: int = storage_size
        # Each node is a list of multiple blocks
        self.tree: list[list[bytes]] = [[] for _ in range(self.storage_size)]

        self.send_message = send_message

        self.blocks_per_bucket = blocks_per_bucket

        self.levels: int = self.storage_size.bit_length()

        # The server starts out full of random encryptions of dummy blocks
        dummy_address: bytes = (256**constants.ADDRESS_SIZE - 1).to_bytes(
            constants.ADDRESS_SIZE, byteorder="big"
        )
        dummy_block: bytes = b"\0" * block_size
        for i in range(self.storage_size):
            for _ in range(self.blocks_per_bucket):
                nonce: bytes = secrets.token_bytes(12)
                encrypted_block = dummy_address + dummy_block + b"\0" * 16
                self.tree[i].append(nonce + encrypted_block)

    def process_command(self, command: bytes) -> None:
        """
        The only exposed method (apart from the initialiser), processes a command from the client.
        Commands are either "Read" or "Write".
        """
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

    def _read_path(self, leaf_node: int) -> bytes:
        """
        Reads a path from the binary tree from root to the given leaf node,
        which is indexed from 0 from the left on the leaf level.
        Reading a path empties that path, because a read is always followed by a write.
        Which fills the path up again.
        Returns all the blocks on the path, concatenated.
        """
        # Adjust leaf node from measuring from the left on the leaf level
        # to measuring including all levels
        leaf_node += self.storage_size // 2
        blocks: list[bytes] = []
        current_node = leaf_node
        for _ in range(self.levels):
            blocks += self.tree[current_node]
            self.tree[current_node] = []
            # Get the parent of the current node
            current_node = (current_node - 1) // 2
        return b"".join(blocks)

    def _process_write_command(self, command: bytes) -> None:
        """
        Writes a block to a certain level along a certain path on the tree.
        The combination of leaf node and level uniquely identifies a bucket.
        Then, the given block is written to the bucket.
        It is the responsibility of the client to not write too many blocks to each bucket.

        A series of these write commands should follow a read.
        The path should be empty after the read, and slowly filled by the write commands.
        """
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


class ServerOram:
    """
    This class manages the storage for many different clients.
    If it receives a command beginning with I, it initialises a new storage.
    Otherwise, it reads the client ID from the command and routes it to the appropriate storage.
    Which is an instance of the class ServerOramPerClient.
    """

    def __init__(
        self,
        send_message: Callable[[bytes], None],
    ):
        self.send_message = send_message
        self.storagePerClient: dict[bytes, ServerOramPerClient] = {}

    def process_command(self, command: bytes) -> None:
        client_id, command = command[:16], command[16:]
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
            self.storagePerClient[client_id] = ServerOramPerClient(
                storage_size=storage_size,
                send_message=self.send_message,
                block_size=block_size,
                blocks_per_bucket=blocks_per_bucket,
            )
            self.send_message(b"ok")
        else:
            self.storagePerClient[client_id].process_command(command)

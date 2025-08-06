import secrets
from typing import Callable, Optional, Union, Union, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import constants
from .bit_util import bit_ceil, get_bucket


import pathoram_client.constants as constants
from pathoram_client.bit_util import bit_ceil, get_bucket


class Oram:
    """The Oram presents the following interface to its users:
    There is a contiguous array of blocks, each containing a number of bytes
    Each block can be accessed by its address in the array, to be read or written to
    The behaviour of reading a block which has not yet been written to is undefined
    The array cannot be resized"""

    def __init__(
        self,
        storage_size: int,
        send_message_read: Callable[[int], bytes],
        send_message_write: Callable[[int, bytes], None],
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
        position_map: Optional[Union[list[bytes], "Oram"]] = None,
        stash: Optional[dict[int, bytes]] = None,
        key: Optional[bytes] = None,
    ):
        """storage_size will be rounded up
        to the nearest power of 2 strictly greater, minus 1.
        For example, to store 6 buckets requires a storage size of 7
        To store 8 buckets requires a storage size of 15
        The maximum storage size supported is 2^64 - 1 buckets

        This class is parameterised over the method of communication to the server

        send_message is a function with the following interface
        send_message(message: bytes) -> bytes
        It returns the response from the server (which might be empty)

        Note that block_size is not the size of the stored blocks,
        as they must also store their address and nonce and auth tag
        But block_size is how much data a user can put into each block

        The position map takes an address as an index
        and returns the leaf node the block at that address is mapped to"""

        # Round up to the nearest power of 2 - 1
        self.storage_size: int = bit_ceil(storage_size + 1) - 1

        self.levels: int = self.storage_size.bit_length()
        self.leaf_nodes: int = (self.storage_size + 1) // 2
        self.block_size = (
            block_size
            + constants.ADDRESS_SIZE
            + constants.NONCE_SIZE
            + constants.AUTH_TAG_SIZE
        )
        self.blocks_per_bucket = blocks_per_bucket

        # A constant block of all 0s to use as a dummy block
        self.dummy_block: bytes = b"\0" * block_size

        if position_map is None:
            self.position_map: Union[list[bytes], Oram] = [
                secrets.randbelow(self.leaf_nodes).to_bytes(
                    constants.LEVEL_SIZE, byteorder="big"
                )
                for _ in range(self.storage_size)
            ]
        else:
            self.position_map = position_map

        if stash is None:
            self.stash: dict[int, bytes] = {}
        else:
            self.stash = stash

        if key is None:
            key = AESGCM.generate_key(bit_length=256)

        self.aes = AESGCM(key)

        self.send_message_read = send_message_read
        self.send_message_write = send_message_write

    def read_block(self, address: int) -> bytes:
        leaf_node = int.from_bytes(self.position_map[address], byteorder="big")
        self._read_block_into_stash(address)
        block = self.stash[address]
        self._write_blocks_from_stash(
            int.from_bytes(
            int.from_bytes(leaf_node, byteorder="big")
        , byteorder="big")
        )
        return block

    def __getitem__(self, address: int) -> bytes:
        return self.read_block(address)

    def __getitem__(self, address: int) -> bytes:
        return self.read_block(address)

    def write_block(self, address: int, block: bytes) -> None:
        leaf_node = int.from_bytes(self.position_map[address], byteorder="big")
        self._read_block_into_stash(address)
        self.stash[address] = block
        self._write_blocks_from_stash(
            int.from_bytes(leaf_node, byteorder="big")
        )

    def __setitem__(self, address: int, block: bytes) -> None:
        return 
            int.from_bytes(self.write_block(address, block, byteorder="big")
        )

    def __setitem__(self, address: int, block: bytes) -> None:
        return self.write_block(address, block)

    def _read_block_into_stash(self, address: int) -> None:
        if not (0 <= address < self.storage_size * self.blocks_per_bucket):
            raise IndexError("address out of range")

        # Remap block to a new leaf node
        old_leaf_node = int.from_bytes(self.position_map[address], byteorder="big")
        self.position_map[address] = secrets.randbelow(self.leaf_nodes).to_bytes(
            constants.LEVEL_SIZE, byteorder="big"
        )

        # If the block is in the stash already, leave it be
        if address in self.stash:
            return

        # Find the leaf node this block is on the path to
        encrypted_blocks = self.send_message_read(old_leaf_node)[1:]
        blocks: list[tuple[int, bytes]] = self.parse_encrypted_blocks(encrypted_blocks)
        for address, block in blocks:
            self.stash[address] = block

    def parse_encrypted_blocks(
        self, encrypted_blocks: bytes
    ) -> list[tuple[int, bytes]]:
        """Takes a byte stream of the form:
        (nonce || ciphertext_block)*
        The nonce is 12 bytes
        The ciphertext_block is self.block_size + 16 bytes
        (The 16 is for the AES authentication tag)
        Once decrypted, each block is of the form:
        address || data
        The address is ADDRESS_SIZE bytes
        The data is DEFAULT_BLOCK_SIZE bytes
        Returns an array of blocks and their addresses with type list[(int, bytes)]
        Note that the bytes object is the data from the format above,
        and no longer contains the address
        If the data cannot be parsed, it will throw a ValueError
        If the address = 256**constants.ADDRESS_SIZE - 1, this is a dummy block,
        so throw it away
        """
        if (
            len(encrypted_blocks)
            != self.block_size * self.levels * self.blocks_per_bucket
        ):
            raise ValueError(
                f"encrypted_blocks must be a bytestream"
                f" with blocks of size {self.block_size}"
                f", but instead has blocks of size"
                f"{len(encrypted_blocks)/self.levels/self.blocks_per_bucket}"
                f", with all blocks being of size {len(encrypted_blocks)}"
            )
        blocks: list[tuple[int, bytes]] = []
        for i in range(0, len(encrypted_blocks), self.block_size):
            nonce = encrypted_blocks[i : i + constants.NONCE_SIZE]
            ciphertext_block = encrypted_blocks[
                i + constants.NONCE_SIZE : i + self.block_size
            ]
            block = self.aes.decrypt(nonce, ciphertext_block, associated_data=None)
            address = int.from_bytes(block[: constants.ADDRESS_SIZE], byteorder="big")
            block = block[constants.ADDRESS_SIZE :]
            if address != 256**constants.ADDRESS_SIZE - 1:
                blocks.append((address, block))
        return blocks

    def _encrypt_and_pack_block(self, address: int, block: bytes) -> bytes:
        """The inverse of parse_encrypted_blocks
        But for a single block
        Used before sending the block to the server"""
        nonce: bytes = secrets.token_bytes(12)
        ciphertext_block: bytes = self.aes.encrypt(
            nonce,
            address.to_bytes(constants.ADDRESS_SIZE, byteorder="big") + block,
            associated_data=None,
        )
        return nonce + ciphertext_block

    def _write_blocks_from_stash(self, leaf_node: int) -> None:
        for i in range(self.levels - 1, -1, -1):
            valid_block_addresses: list[int] = []
            for block_address in self.stash.keys():
                block_leaf_node = int.from_bytes(
                    self.position_map[block_address], byteorder="big"
                )
                if (
                    get_bucket(block_leaf_node, i, self.levels)
                    == get_bucket(leaf_node, i, self.levels)
                    and len(valid_block_addresses) <= self.blocks_per_bucket
                ):
                    valid_block_addresses.append(block_address)
            valid_blocks = [
                self._encrypt_and_pack_block(address, self.stash[address])
                for address in valid_block_addresses
            ]
            # Pad with dummy blocks
            while len(valid_blocks) < self.blocks_per_bucket:
                valid_blocks.append(
                    self._encrypt_and_pack_block(
                        256**constants.ADDRESS_SIZE - 1, self.dummy_block
                    )
                )
            for block in valid_blocks:
                self.send_message_write(
                    leaf_node, i.to_bytes(constants.LEVEL_SIZE, byteorder="big") + block
                )
            for address in valid_block_addresses:
                self.stash.pop(address)


class OramRecursive:
    """Recursive variant of Oram with uniform block size at each level of recursive"""

    def __init__(
        self,
        storage_size: int,
        send_message_read: Callable[[int], bytes],
        send_message_write: Callable[[int, bytes], None],
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
        recursive_depth: int = constants.DEFAULT_RECURSIVE_DEPTH,
        stash: Optional[dict[int, bytes]] = None,
        key: Optional[bytes] = None,
    ):
        self.orams: list[Oram] = []
        for i in range(recursive_depth):
            self.orams.append(
                Oram(
                    storage_size=storage_size,
                    send_message_read=lambda addr: send_message_read(
                        addr + i * storage_size
                    ),
                    send_message_write=lambda addr, data: send_message_write(
                        addr + i * storage_size, data
                    ),
                    block_size=block_size,
                    blocks_per_bucket=blocks_per_bucket,
                    position_map=self.orams[i - 1] if self.orams else None,
                    stash=stash,
                    key=key,
                )
            )
        self.orams.append(
            Oram(
                storage_size=storage_size,
                send_message_read=lambda addr: send_message_read(
                    addr + recursive_depth * storage_size
                ),
                send_message_write=lambda addr, data: send_message_write(
                    addr + recursive_depth * storage_size, data
                ),
                block_size=block_size,
                blocks_per_bucket=blocks_per_bucket,
                position_map=self.orams[-1] if self.orams else None,
                stash=stash,
                key=key,
            )
        )

    def read_block(self, address: int) -> bytes:
        return self.orams[-1].read_block(address)

    def __getitem__(self, address: int) -> bytes:
        return self.read_block(address)

    def write_block(self, address: int, block: bytes) -> None:
        self.orams[-1].write_block(address, block)

    def __setitem__(self, address: int, block: bytes) -> None:
        return self.write_block(address, block)

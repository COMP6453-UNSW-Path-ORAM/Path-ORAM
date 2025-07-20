import math
import secrets
from collections.abc import Callable
from typing import Optional

import constants
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Oram:
    """The Oram presents the following interface to its users:
    There is a contiguous array of blocks, each containing a number of bytes
    Each block can be accessed by its address in the array, to be read or written to
    The behaviour of reading a block which has not yet been written to is undefined
    The array cannot be resized"""

    def __init__(
        self,
        storage_size: int,
        send_message: Callable[[bytes], bytes],
        block_size: int = constants.DEFAULT_BLOCK_SIZE,
        blocks_per_bucket: int = constants.DEFAULT_BLOCKS_PER_BUCKET,
        position_map: Optional[list[int]] = None,
        stash: Optional[dict[int, bytes]] = None,
        key: Optional[bytes] = None,
    ):
        """storage_size will be rounded up to the nearest power of 2.
        The maximum storage size supported is 2^64 - 1 buckets
        This class is parameterised over the method of communication to the server
        send_message is a function with the following interface
        send_message(message: bytes) -> bytes
        It returns the response from the server (which might be empty)
        Note that block_size is not the size of the stored blocks, as they must also store
        their address and nonce
        But block_size is how much data a user can put into each block
        The position map takes an address as an index and returns the leaf node the block
        at that address is mapped to"""

        # Adding 1 to the storage size is necessary for dummy addresses,
        # and then the rest of it rounds up to the nearest power of 2
        storage_size += 1
        self.storage_size: int = int(math.pow(math.ceil(math.log2(storage_size)), 2))

        self.leaf_nodes: int = int(storage_size / 2)
        self.levels: int = int(math.ceil(math.log2(self.storage_size)))
        self.block_size = block_size + constants.ADDRESS_SIZE + constants.NONCE_SIZE
        self.blocks_per_bucket = blocks_per_bucket

        # A constant block of all 0s to use as a dummy block
        self.dummy_block: bytes = b"\0" * block_size

        if position_map is None:
            self.position_map: list[int] = [
                secrets.choice(range(0, self.leaf_nodes))
                for _ in range(0, self.storage_size)
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

        self.send_message = send_message

    def read_block(self, address: int) -> bytes:
        self._read_block_into_stash(address)
        block = self.stash[address]
        self._write_blocks_from_stash(self.position_map[address])
        return block

    def write_block(self, address: int, block: bytes) -> None:
        self._read_block_into_stash(address)
        self.stash[address] = block
        self._write_blocks_from_stash(self.position_map[address])

    def _read_block_into_stash(self, address: int) -> None:
        if address < 0 or address >= self.storage_size * self.blocks_per_bucket:
            raise IndexError

        # Remap block to a new leaf node
        old_leaf_node = self.position_map[address]
        self.position_map[address] = secrets.randbelow(self.leaf_nodes)

        # If the block is in the stash already, leave it be
        if address in self.stash:
            return

        # Find the leaf node this block is on the path to
        encrypted_blocks = self.send_message(
            b"READ " + str(old_leaf_node).encode("utf-8")
        )
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
        If the address = storage_size - 1, this is a dummy block, so throw it away"""
        i = 0
        blocks: list[tuple[int, bytes]] = []
        while i < len(encrypted_blocks):
            nonce = encrypted_blocks[i : i + constants.NONCE_SIZE]
            ciphertext_block = encrypted_blocks[
                i + constants.NONCE_SIZE : i + self.block_size
            ]
            i += self.block_size
            block = self.aes.decrypt(nonce, ciphertext_block, associated_data=None)
            address = int.from_bytes(block[: constants.ADDRESS_SIZE], byteorder="big")
            if address != self.storage_size - 1:
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
        # Note that i=0 refers to the bottom level,
        # and i = self.levels-1 to the root node
        for i in range(0, self.levels):
            valid_block_addresses = []
            for block_address in self.stash.keys():
                # We want to check if the path to the leaf node of this block coincides
                # with the path to the leaf node we care about at the level we are on
                # On the bottom level, both leaf nodes must be identical
                # On the next level, nodes 0 and 1 have intersecting paths,
                # as do 1 and 2, and 3 and 4
                # On the next level, nodes 0, 1, 2, 3 have intersection paths,
                # as do 4, 5, 6, 7
                # So, to check if we are equal,
                # we can divide by 2^(distance_from_bottom_level)
                # and then round down. Dividing by 4 and rounding down,
                # 0, 1, 2, 3, are the same number
                # Just like we want
                block_leaf_node = self.position_map[block_address]
                if math.floor(block_leaf_node / (2**i)) == math.floor(
                    leaf_node / (2**i)
                ):
                    valid_block_addresses.append(block_address)
            valid_block_addresses = valid_block_addresses[: self.blocks_per_bucket]
            valid_blocks = [
                self._encrypt_and_pack_block(address, self.stash[address])
                for address in valid_block_addresses
            ]
            while len(valid_blocks) < self.blocks_per_bucket:
                # The largest address is reserved for dummy blocks
                valid_blocks.append(
                    self._encrypt_and_pack_block(
                        self.storage_size - 1, self.dummy_block
                    )
                )
            for block in valid_blocks:
                self.send_message(
                    b"WRITE LEAF NODE "
                    + leaf_node.to_bytes(constants.ADDRESS_SIZE, byteorder="big")
                    + b" LEVEL "
                    + (self.levels - i - 1).to_bytes(
                        constants.LEVEL_SIZE, byteorder="big"
                    )
                    + b" BLOCK "
                    + block
                )
            for address in valid_block_addresses:
                self.stash.pop(address)

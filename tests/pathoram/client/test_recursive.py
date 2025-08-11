import unittest
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathoram.client import ClientOramRecursive, constants


class DummyComm:
    def __init__(self, levels, blocks_per_bucket):
        self.storage = {}
        self.key = AESGCM.generate_key(bit_length=256)
        self.aes = AESGCM(self.key)
        self.levels = levels
        self.blocks_per_bucket = blocks_per_bucket
        self.block_data_size = constants.DEFAULT_BLOCK_SIZE

    def send_message_init(self, client_id, storage_size, block_size, blocks_per_bucket):
        self.storage[client_id] = {}

    def send_message_read(self, client_id, leaf_node):
        blocks = []
        client_storage = self.storage.get(client_id, {})

        addresses = list(client_storage.keys())

        for address in addresses[: self.levels * self.blocks_per_bucket]:
            block_data = client_storage[address]
            nonce = secrets.token_bytes(constants.NONCE_SIZE)
            plaintext = address.to_bytes(constants.ADDRESS_SIZE, "big") + block_data
            ciphertext = self.aes.encrypt(nonce, plaintext, associated_data=None)
            blocks.append(nonce + ciphertext)

        dummy_address_bytes = (256 ** constants.ADDRESS_SIZE - 1).to_bytes(constants.ADDRESS_SIZE, "big")
        while len(blocks) < self.levels * self.blocks_per_bucket:
            nonce = secrets.token_bytes(constants.NONCE_SIZE)
            plaintext = dummy_address_bytes + b"\0" * self.block_data_size
            ciphertext = self.aes.encrypt(nonce, plaintext, associated_data=None)
            blocks.append(nonce + ciphertext)

        return b"\x00" + b"".join(blocks)

    def send_message_write(self, client_id, leaf_node, data):
        client_storage = self.storage.setdefault(client_id, {})

        block_size = (
            self.block_data_size
            + constants.ADDRESS_SIZE
            + constants.NONCE_SIZE
            + constants.AUTH_TAG_SIZE
        )

        i = 0
        while i < len(data):
            # skip LEVEL_SIZE bytes
            level_bytes = data[i : i + constants.LEVEL_SIZE]
            i += constants.LEVEL_SIZE

            nonce = data[i : i + constants.NONCE_SIZE]
            i += constants.NONCE_SIZE

            ciphertext_block = data[i : i + block_size - constants.NONCE_SIZE]
            i += block_size - constants.NONCE_SIZE

            plaintext = self.aes.decrypt(nonce, ciphertext_block, associated_data=None)
            address = int.from_bytes(plaintext[: constants.ADDRESS_SIZE], "big")
            block = plaintext[constants.ADDRESS_SIZE :]

            # skip dummy blocks
            if address != 256**constants.ADDRESS_SIZE - 1:
                client_storage[address] = block


class TestClientOramRecursive(unittest.TestCase):
    def setUp(self):
        storage_size = 16
        blocks_per_bucket = constants.DEFAULT_BLOCKS_PER_BUCKET
        levels = (storage_size + 1).bit_length()

        self.comm = DummyComm(levels=levels, blocks_per_bucket=blocks_per_bucket)
        self.rec_oram = ClientOramRecursive(
            storage_size=storage_size,
            send_message_init=self.comm.send_message_init,
            send_message_read=self.comm.send_message_read,
            send_message_write=self.comm.send_message_write,
            key=self.comm.key,
        )

    def test_read_write_block(self):
        address = 5
        data = b"hello world!".ljust(constants.DEFAULT_BLOCK_SIZE, b"\0")

        self.rec_oram.write_block(address, data)
        read_data = self.rec_oram.read_block(address)

        self.assertEqual(read_data[: len(data)], data)

    def test_stash_persistence(self):
        addr1 = 3
        data1 = b"data1".ljust(constants.DEFAULT_BLOCK_SIZE, b"\0")
        addr2 = 7
        data2 = b"data2".ljust(constants.DEFAULT_BLOCK_SIZE, b"\0")

        self.rec_oram.write_block(addr1, data1)
        self.rec_oram.write_block(addr2, data2)

        read1 = self.rec_oram.read_block(addr1)
        read2 = self.rec_oram.read_block(addr2)

        self.assertEqual(read1[: len(data1)], data1)
        self.assertEqual(read2[: len(data2)], data2)

    def test_orams_structure(self):
        self.assertTrue(hasattr(self.rec_oram, "orams"))
        self.assertGreater(len(self.rec_oram.orams), 0)
        for oram in self.rec_oram.orams:
            self.assertTrue(hasattr(oram, "read_block"))
            self.assertTrue(hasattr(oram, "write_block"))

    def test_write_and_read_multiple_blocks(self):
        blocks = {
            0: b"block0".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x01"),
            1: b"block1".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x02"),
            2: b"block2".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x03"),
            15: b"block15".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x04"),
        }
        for addr, data in blocks.items():
            self.rec_oram.write_block(addr, data)

        for addr, data in blocks.items():
            read_data = self.rec_oram.read_block(addr)
            self.assertEqual(read_data[: len(data)], data)

    def test_overwrite_block(self):
        addr = 8
        data1 = b"first write".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x05")
        data2 = b"second write".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x06")

        self.rec_oram.write_block(addr, data1)
        read1 = self.rec_oram.read_block(addr)
        self.assertEqual(read1[: len(data1)], data1)

        self.rec_oram.write_block(addr, data2)
        read2 = self.rec_oram.read_block(addr)
        self.assertEqual(read2[: len(data2)], data2)

    def test_write_and_read_boundary_addresses(self):
        min_addr = 0
        max_addr = self.rec_oram.orams[-1].storage_size - 1


        min_data = b"min address".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x07")
        max_data = b"max address".ljust(constants.DEFAULT_BLOCK_SIZE, b"\x08")

        self.rec_oram.write_block(min_addr, min_data)
        self.rec_oram.write_block(max_addr, max_data)

        read_min = self.rec_oram.read_block(min_addr)
        read_max = self.rec_oram.read_block(max_addr)

        self.assertEqual(read_min[: len(min_data)], min_data)
        self.assertEqual(read_max[: len(max_data)], max_data)


if __name__ == "__main__":
    unittest.main()
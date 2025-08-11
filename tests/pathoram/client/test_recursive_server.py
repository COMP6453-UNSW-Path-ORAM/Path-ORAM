import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathoram.client import ClientOramRecursive, constants
from pathoram.server import ServerOram

CLIENT_ID = b"\x00" * 16  # Constant clientId

class TestClientOramRecursiveWithServer(unittest.TestCase):
    def setUp(self):
        storage_size = 16
        blocks_per_bucket = constants.DEFAULT_BLOCKS_PER_BUCKET

        self.server_responses = []

        def send_message(data: bytes):
            self.server_responses.append(data)

        self.key = AESGCM.generate_key(bit_length=256)
        self.server = ServerOram(send_message=send_message, key=self.key)

        self.rec_oram = ClientOramRecursive(
            storage_size=storage_size,
            send_message_init=self.send_init,
            send_message_read=self.send_read,
            send_message_write=self.send_write,
            key=self.key,
        )

    def send_init(self, _, storage_size, block_size, blocks_per_bucket):
        command = (
            CLIENT_ID
            + b"I"
            + storage_size.to_bytes(constants.ADDRESS_SIZE, "big")
            + block_size.to_bytes(constants.ADDRESS_SIZE, "big")
            + blocks_per_bucket.to_bytes(constants.ADDRESS_SIZE, "big")
        )
        self.server_responses.clear()
        self.server.process_command(command)
        response = self.server_responses.pop()
        self.assertEqual(response, b"ok")

    def send_read(self, _, leaf_node):
        command = CLIENT_ID + b"R" + leaf_node.to_bytes(constants.ADDRESS_SIZE, "big")
        self.server_responses.clear()
        self.server.process_command(command)
        response = self.server_responses.pop()
        self.assertTrue(response.startswith(b"R"))
        return response[1:]

    def send_write(self, _, leaf_node, data):
        command = CLIENT_ID + b"W" + leaf_node.to_bytes(constants.ADDRESS_SIZE, "big") + data
        self.server_responses.clear()
        self.server.process_command(command)
        response = self.server_responses.pop()
        self.assertEqual(response, b"ok")


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

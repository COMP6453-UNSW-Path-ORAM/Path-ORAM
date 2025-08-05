import pathoram_client.constants as constants
from pathoram_client.pathoram_client import Oram


def read_bytes(addr: int) -> bytes:
    cmd = b"R" + addr.to_bytes(constants.ADDRESS_SIZE, byteorder="big")
    print(cmd)
    return b""


def write_bytes(addr: int, data: bytes) -> None:
    cmd = (
        b"W"
        + addr.to_bytes(constants.ADDRESS_SIZE, byteorder="big")
        + data
    )
    print(cmd)


O = Oram(100, read_bytes, write_bytes)
print(O)
O[1] = b"hi"
print(O[1])

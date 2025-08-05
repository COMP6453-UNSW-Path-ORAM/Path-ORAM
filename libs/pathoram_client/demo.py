import pathoram_client.constants as constants
from pathoram_client.pathoram_client import Oram

M = {}

def read_bytes(addr: int) -> bytes:
    cmd = b"R" + addr.to_bytes(constants.ADDRESS_SIZE, byteorder="big")
    res = M.get(addr, b"")
    print("R", addr, res)
    return res


def write_bytes(addr: int, data: bytes) -> None:
    print("W", addr)
    M[addr] = data
    cmd = (
        b"W"
        + addr.to_bytes(constants.ADDRESS_SIZE, byteorder="big")
        + data
    )
    # print(cmd)


O = Oram(100, read_bytes, write_bytes)
print(O)
O[0] = b"hi"
print(O[0])

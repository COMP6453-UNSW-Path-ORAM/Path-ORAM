import unittest

from pathoram.client import bit_util


class TestBitCeil(unittest.TestCase):
    def test_bit_ceil_0(self) -> None:
        self.assertEqual(bit_util.bit_ceil(0), 1)

    def test_bit_ceil_1(self) -> None:
        self.assertEqual(bit_util.bit_ceil(1), 1)

    def test_bit_ceil_2(self) -> None:
        self.assertEqual(bit_util.bit_ceil(2), 2)

    def test_bit_ceil_pow2_minus_one(self) -> None:
        self.assertEqual(bit_util.bit_ceil(127), 128)

    def test_bit_ceil_pow2(self) -> None:
        self.assertEqual(bit_util.bit_ceil(128), 128)

    def test_bit_ceil_pow2_plus_one(self) -> None:
        self.assertEqual(bit_util.bit_ceil(129), 256)


if __name__ == "__main__":
    unittest.main()

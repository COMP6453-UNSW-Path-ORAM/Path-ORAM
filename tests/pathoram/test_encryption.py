'''encryption tests.'''

import pytest

from test_setup import TestOram, pad

@pytest.fixture(params=[127, 15, 16383, 100000], ids=["basic", "small", "big", "huge"])
def oram_instance(request):
    '''fixture that takes variable sized orams.'''
    oram = TestOram()
    oram.setup(storage_size=request.param)
    yield oram
    oram.teardown()

@pytest.fixture
def oram_instance_specific():
    '''for single size oram use.'''
    oram = TestOram()
    oram.setup(storage_size=15)
    yield oram
    oram.teardown()

def test_enc_block_size(oram_instance):
    '''test encrypted blocks are same size.'''
    data = pad(b"hello world")
    data2 = pad(b"abcd")
    oram_instance.client_oram.write_block(0, data)
    oram_instance.client_oram.write_block(1, data2)

    result = oram_instance.client_oram.read_block(0)
    assert result == data

# def test_enc_dec(oram_instance):
#     '''test encryption and decryption functionality for data blocks.'''


# def test_same_data_diff_enc(oram_instance):
#     '''test same data encrypts differently.'''


# def test_bitflip(oram_instance):
#     '''
#     test valid encryption.
#     eg flip a byte and decrypt functionality should send an error.
#     '''

# def test_check_buckets_all_enc(oram_instance_specific):
#     '''test all contents in each bucket are encrypted.'''

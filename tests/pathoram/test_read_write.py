'''tests for basic read and write functionality of client to server.'''

import pytest
import random

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

def test_read_write(oram_instance):
    '''test basic single read and write case.'''
    data = pad(b"abcd")
    oram_instance.client_oram.write_block(0, data)
    result = oram_instance.client_oram.read_block(0)
    assert result == data

def test_overwrite(oram_instance):
    '''test second write overwrites content.'''
    data = pad(b"aaaaaaa")
    data2 = pad(b"bbb")
    oram_instance.client_oram.write_block(0, data)
    oram_instance.client_oram.write_block(0, data2)
    result = oram_instance.client_oram.read_block(0)
    assert result == data2

def test_multi_read(oram_instance):
    '''test multiple reads should not change data.'''
    data = pad(b"aaaaaaa")
    oram_instance.client_oram.write_block(0, data)
    result = oram_instance.client_oram.read_block(0)
    result2 = oram_instance.client_oram.read_block(0)
    result3 = oram_instance.client_oram.read_block(0)
    assert result == data
    assert result2 == data
    assert result3 == data

def test_client_read_posmap(oram_instance):
    '''
    test leaf node for block is changed after every access.
    exposes client-side position map for testing.
    '''
    data = pad(b"aaaaaaa")
    oram_instance.client_oram.write_block(0, data)
    init_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    oram_instance.client_oram.read_block(0)
    mid_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    assert init_leaf != mid_leaf
    result = oram_instance.client_oram.read_block(0)
    res_leaf = int.from_bytes(oram_instance.client_oram.position_map[0], byteorder="big")
    assert mid_leaf != res_leaf
    assert data == result

def test_multi_ops(oram_instance_specific):
    '''test handling of multiple read and write operations.'''
    data = pad(b"aaaaaaa")
    data2 = pad(b"hello world")
    data3 = pad(b"b")
    data4 = pad(b"c")
    data5 = pad(b"d")
    oram_instance_specific.client_oram.write_block(0, data)
    oram_instance_specific.client_oram.write_block(1, data2)
    result = oram_instance_specific.client_oram.read_block(0)
    oram_instance_specific.client_oram.write_block(5, data3)
    result2 = oram_instance_specific.client_oram.read_block(1)
    result3 = oram_instance_specific.client_oram.read_block(5)
    oram_instance_specific.client_oram.write_block(7, data4)
    oram_instance_specific.client_oram.write_block(0, data5)
    result4 = oram_instance_specific.client_oram.read_block(0)
    result5 = oram_instance_specific.client_oram.read_block(7)
    assert data == result
    assert data2 == result2
    assert data3 == result3
    assert data5 == result4
    assert data4 == result5

def test_multi_ops_plus(oram_instance):
    '''test handling of multiple read and write operations.'''
    data_arr = [b"aaa", b"bbbbb", b"cccccc", b"dd", b"e"]
    valid_addresses = []
    for i in range(1000):
        addr = random.randint(0,oram_instance.storage_size-1)
        data = pad(data_arr[i%5])
        oram_instance.client_oram.write_block(addr, data)
        # valid_addresses.append(addr)
        # valid_addr = random.choice(valid_addresses)
        # result = oram_instance.client_oram.read_block(valid_addr)
        # assert result == oram_instance.client_oram.position_map[valid_addr]

def test_nonexistent_read(oram_instance_specific):
    '''test that reading blocks without writing anything should 
       not return any actual data, instead throw error.'''
    with pytest.raises(KeyError):
        for i in range(15):
            oram_instance_specific.client_oram.read_block(i)

def test_bad_data_len(oram_instance):
    '''test invalid data len raises error'''
    with pytest.raises(ValueError):
        data_arr = [b"hi", "hi", "", b"", pad(b"aaa")+b"a", pad(b"aaa")+pad(b"aaa")]
        for bad_len_data in data_arr:
            oram_instance.client_oram.write_block(0, bad_len_data)


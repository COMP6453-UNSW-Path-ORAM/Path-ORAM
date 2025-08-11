import pytest

from test_setup import TestOram, pad, DEFAULT_BLOCK_SIZE

@pytest.fixture
def oram_instance(request):
    oram = TestOram()
    oram.setup(storage_size=100000)
    yield oram
    oram.teardown()

def test_real_data(oram_instance):
    '''test uploading and reading (procedurally generatred) real world data.
       We generated plausible customer records using mockaroo.com to test data
       that a business would plausibly want to obscure their access patterns to.'''
    data = b""
    with open('real_world_data.csv', 'rb') as file:
        data = file.read()

    padded_data_list: list[bytes] = []
    for i in range(0, len(data), DEFAULT_BLOCK_SIZE):
        block = data[i : i + DEFAULT_BLOCK_SIZE]
        if len(block) < DEFAULT_BLOCK_SIZE:
            block = pad(block)
        oram_instance.client_oram.write_block(i, block)
        padded_data_list.append(block)
    padded_data = b"".join(padded_data_list)

    result_list: list[bytes] = []
    for i in range(0, len(data), DEFAULT_BLOCK_SIZE):
        result_list.append(oram_instance.client_oram.read_block(i))
    result = b"".join(result_list)

    assert padded_data == result

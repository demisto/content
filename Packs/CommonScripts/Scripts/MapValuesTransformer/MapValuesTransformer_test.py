from MapValuesTransformer import mapvalues


def test_mapvalues_dict():
    value = {
        "testkey1": "testvalue1",
        "testkey2": "testvalue2"
    }
    input_v = "testkey2: testvalue2"
    mapped_v = "testvalue2changed"
    assert mapvalues(value, input_v, mapped_v) == '{"testkey1": "testvalue1", "testkey2": "testvalue2changed"}'


def test_mapvalues_str():
    value = "3"
    input_v = "4,3,2,1"
    mapped_v = "1,2,3,4"
    assert mapvalues(value, input_v, mapped_v) == "2"


def test_mapvalues_int():
    value = 3
    input_v = "4,3,2,1"
    mapped_v = "1,2,3,4"
    assert mapvalues(value, input_v, mapped_v) == "2"


def test_mapvalues_dict_abnorm():
    value = {
        "testkey1": "testvalue1",
        "testkey2": "testvalue2"
    }
    input_v = "testkey2:testvalue2"
    mapped_v = "testvalue2changed"
    assert mapvalues(value, input_v, mapped_v) == '{"testkey1": "testvalue1", "testkey2": "testvalue2changed"}'

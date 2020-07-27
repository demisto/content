from MapValuesTransformer import mapValues


def test_mapvalues():

    value = {
        "testkey1": "testvalue1",
        "testkey2": "testvalue2"
    }
    input_v = "testkey2: testvalue2"
    mapped_v = "testvalue2changed"
    assert mapValues(value, input_v, mapped_v) == '{"testkey1": "testvalue1", "testkey2": "testvalue2changed"}'

    value = "3"
    input_v = "4,3,2,1"
    mapped_v = "1,2,3,4"
    assert mapValues(value, input_v, mapped_v) == "2"

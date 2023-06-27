from GetDataCollectionLink import encode_string, get_data_collection_url


def test_main():
    assert encode_string('abcde') == '59574a6a5a47553d'
    assert get_data_collection_url('1', ['t']) == [
        {'task': '1@1', 'url': 'https://test-address:8443/#/external/form/4d554178/64413d3d', 'user': 't'}]

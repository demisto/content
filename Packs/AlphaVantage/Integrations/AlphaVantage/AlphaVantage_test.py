import pytest

from AlphaVantage import remove_indexing_from_dictionary_keys


@pytest.mark.parametrize('key, transformed', [
    ('01.This', 'This'),
    ('01. This', 'This')
])
def test_remove_indexing_from_dictionary_keys(key: str, transformed: str):
    value = 'value'
    test_dict = {key: value}
    assert remove_indexing_from_dictionary_keys(test_dict) == {transformed: value}

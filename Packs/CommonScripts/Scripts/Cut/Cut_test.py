from Cut import cut

import pytest


@pytest.mark.parametrize("value,delimiter,fields,,expected",
    [
        ('A-B-C-D-E', '-', '1,5', 'A-E'),
        ('a,ב,c', ',', '2,3', 'ב,c'),
    ]
)
def test_cut(value, delimiter, fields, expected):
    assert cut(value, fields, delimiter) == expected

import pytest


def side_effect_demisto_getFilePath(entry_id):
    return {'path': entry_id}


cases = [
    ('text-based-protocol', b'example', 'example'),
    ('text-based-protocol', b'hello\nworld', 'hello\nworld'),
    ('human-readable', b'example', 'example'),
]


@pytest.mark.parametrize('protocol,value,expected', cases)
def test_from_bytes_to_text(protocol, value, expected):
    from PcapExtractStreams import from_bytes_to_text

    res = from_bytes_to_text(protocol, value)
    assert res == expected

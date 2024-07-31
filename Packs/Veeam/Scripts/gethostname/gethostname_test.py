import pytest
from gethostname import find_host


@pytest.mark.parametrize("data, expected", [
    ([{'urn': 'hostsystem:foo'},
      {'urn': 'hostsystem:bar'}],
     'foo'),
    ([{'urn': 'hostsystem:baz'},
      {'urn': 'folder:123'}],
     'baz'),
    ([{'urn': 'folder:321'},
      {'urn': 'folder:789'}],
     ''),
])
def test_find_host(data, expected):
    assert find_host(data) == expected

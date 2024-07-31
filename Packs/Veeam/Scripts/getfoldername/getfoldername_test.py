import pytest
from getfoldername import find_folder


@pytest.mark.parametrize("data, expected", [
    (
        [{'urn': 'folder:123;folder:group-v456'},
         {'urn': 'folder:789'},
         {'urn': 'folder:group-v987;folder:group-v654'}],
        'group-v456'
    ),
    (
        [{'urn': 'host:123'},
         {'urn': 'host:789'}],
        ''
    ),
    (
        [{'urn': 'folder:group-v456'}],
        'group-v456'
    ),
])
def test_find_folder(data, expected):
    assert find_folder(data) == expected

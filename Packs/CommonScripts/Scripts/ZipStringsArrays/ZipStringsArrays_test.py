import pytest

TEST_CASES = [
    ({'list1': [], 'list2': ['a', 'b']}, []),
    ({'list1': ['a', 'b'], 'list2': []}, []),
    ({'list1': ['c', 'd'], 'list2': ['a', 'b']}, ['c-a', 'd-b']),
    ({'list1': [], 'list2': ['a', 'b'], 'format': '{2}-{1}'}, []),
    ({'list1': ['a', 'b'], 'list2': [], 'format': '{1}-{2}'}, []),
    ({'list1': ['c', 'd'], 'list2': ['a', 'b'], 'format': '{1}/{2}'}, ['c/a', 'd/b']),
    ({'list1': "aa", 'list2': "bb", 'format': '{1}/{2}'}, ['aa/bb']),
    ({'list1': "", 'list2': "", 'format': '{1}/{2}'}, []),
    ({'list1': "[\"aa\"]", 'list2': "[\"bb\"]", 'format': '{1}/{2}'}, ['aa/bb']),
]


@pytest.mark.parametrize('args, expected', TEST_CASES)
def test_mapper_command(mocker, args, expected):
    from ZipStringsArrays import mapper_command
    res = mapper_command(args)
    assert res.outputs.get('zipped_list') == expected

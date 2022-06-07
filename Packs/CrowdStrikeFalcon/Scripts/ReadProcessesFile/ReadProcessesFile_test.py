import pytest

from ReadProcessesFile import *


@pytest.mark.parametrize('context, expected_file_name', [
    ({"ps": [{'Filename': "first"}, {'Filename': "second"}]}, "second"),
    ({"ps": [{'Filename': "first"}]}, "first"),
    ({"ps": []}, ""),
    ({'ps': {"Filename": "first"}}, "first"),
    ({}, ""),
])
def test_get_file_name_from_context(mocker, context, expected_file_name):
    mocker.patch.object(demisto, 'context', return_value={'CrowdStrike': {'Command': context}})
    assert get_file_name_from_context() == expected_file_name


def test_get_file_name_from_context_list(mocker):
    context = {'CrowdStrike': [{'NotCommand': ''}, {'Command': {'ps': {"Filename": "first"}}}]}
    mocker.patch.object(demisto, 'context', return_value=context)
    assert get_file_name_from_context() == 'first'


@pytest.mark.parametrize('file_name_in_context, file_name_in_to_search, expected_entry_id', [
    ("name1", "name1", "1"),
    ("name1", "name2", ""),
])
def test_get_file_entry_id(mocker, file_name_in_context, file_name_in_to_search, expected_entry_id):
    mocker.patch.object(demisto, 'executeCommand', return_value=[{"ID": "1"}])
    mocker.patch.object(demisto, 'get', return_value=file_name_in_context)
    assert get_file_entry_id(file_name_in_to_search) == expected_entry_id

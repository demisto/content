from ContextSetup import *
import pytest

incident_contains_field_in_root = {
    'field_name': 'Test',
    'id': 2,
    'name': 'This is incident2',
    'CustomFields': {
        'urlsslverification': [{'entryid': 'abcd', 'link': '1234'},
                               {'entryid': 'abcd', 'link': '1234'}]
    }
}


def test_append(mocker):
    args = {'keys': 'Link,EntryID,TimeStamp', 'val1': 'www.google.com', 'val2': 'AWS', 'val3': 'TIMESTAMP',
            'context_key': 'urlsslverification'}
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, 'executeCommand', return_value='Done')
    entry = context_setup_command(args)
    assert entry == 'Done'


def test_overwrite(mocker):
    args = {'keys': 'Link,EntryID', 'val1': 'www.google.com', 'val2': 'AWS', 'context_key': 'urlsslverification',
            'overwrite': "true"}
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, 'executeCommand', return_value='Done')
    entry = context_setup_command(args)
    assert entry == 'Done'


def test_error(mocker):
    args = {'keys': 'Link', 'val1': 'www.google.com', 'val2': 'AWS', 'context_key': 'urlsslverification',
            'overwrite': "true"}
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    mocker.patch.object(demisto, 'executeCommand', return_value='Done')
    with pytest.raises(ValueError):
        context_setup_command(args)

from CommonServerPython import *
from CheckContextValue import poll_field

context = {
    'id': 1,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'foo': 'bar',
}

missing_context = {
    'id': 2,
    'name': 'This is incident2',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
}


def test_poll_context_field_from_root(mocker):
    """ Unit test
    Given
        - An incident with the context field named 'foo' with value 'bar' in the root
        - The regex sent is matching the field value
    When
        - mock the server response to demisto.context().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'context', return_value=context)
    args = {
        'key': 'foo',
    }

    result = poll_field(args)

    assert result.readable_output in "The key exists."
    assert result.outputs['exists'] is True


def test_poll_context_field_from_root_with_regex_failure(mocker):
    """ Unit test
    Given
        - An incident with the context field named 'foo' with value 'bar' in the root
        - The regex sent does not match the context field value
    When
        - mock the server response to demisto.context().
    Then
        Validate the script returns a false value
    """
    mocker.patch.object(demisto, 'context', return_value=context)
    args = {
        'key': 'foo',
        'regex': '^a',
    }

    result = poll_field(args)

    assert result.readable_output in "The key does not exist."
    assert result.outputs['exists'] is False


def test_poll_field_from_root_with_regex_success(mocker):
    """ Unit test
    Given
        - An incident with the context field named 'foo' with value 'bar' in root
        - No regex argument sent to the command
    When
        - mock the server response to demisto.context().
    Then
        Validate the script finds the context field
    """
    mocker.patch.object(demisto, 'context', return_value=context)
    args = {
        'key': 'foo',
        'regex': '^b',
    }

    result = poll_field(args)

    assert result.readable_output in "The key exists."
    assert result.outputs['exists'] is True


def test_poll_missing_context_field_in_root(mocker):
    """ Unit test
    Given
        - An incident without the context field named 'foo' in the root
    When
        - mock the server response to demisto.context().
    Then
        Validate the script returns a false value
    """
    mocker.patch.object(demisto, 'context', return_value=missing_context)
    args = {
        'key': 'foo',
    }

    result = poll_field(args)

    assert result.readable_output in "The key does not exist."
    assert result.outputs['exists'] is False

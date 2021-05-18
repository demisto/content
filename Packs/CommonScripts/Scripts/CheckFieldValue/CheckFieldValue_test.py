from CommonServerPython import *
from CheckFieldValue import poll_field

incident_contains_field_in_custom_fields = {
    'id': 1,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}],
    'CustomFields': {
        'field_name': 'Test'
    }
}

incident_with_empty_field_in_custom_fields = {
    'id': 1,
    'name': 'This is incident1',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}],
    'CustomFields': {
        'field_name': ''
    }
}

incident_contains_field_in_root = {
    'field_name': 'Test',
    'id': 2,
    'name': 'This is incident2',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}

incident_without_field = {
    'id': 3,
    'name': 'This is incident3',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}

incident_with_empty_field = {
    'field_name': '',
    'id': 3,
    'name': 'This is incident3',
    'type': 'Phishing',
    'severity': 0,
    'status': 1,
    'created': '2019-01-02',
    'closed': '0001-01-01T00:00:00Z',
    'labels': [{'type': 'subject', 'value': 'This subject1'}, {'type': 'unique', 'value': 'This subject1'}],
    'attachment': [{'name': 'Test word1 word2'}]
}


def test_poll_field_from_root_with_regex_success(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in the root
        - The regex sent is matching the field value
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    args = {
        'field': 'field_name',
        'regex': '^Test',
    }

    result = poll_field(args)

    assert result.readable_output in "The field exists."
    assert result.outputs['exists'] is True


def test_poll_field_from_root_with_regex_failure(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in the root
        - The regex sent does not match the field value
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script returns a false value
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    args = {
        'field': 'field_name',
        'regex': '^Testing',
    }

    result = poll_field(args)

    assert result.readable_output in "The field does not exist."
    assert result.outputs['exists'] is False


def test_poll_field_from_root_without_regex_success(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in root
        - No regex argument sent to the command
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_root])
    args = {
        'field': 'field_name',
    }

    result = poll_field(args)

    assert result.readable_output in "The field exists."
    assert result.outputs['exists'] is True


def test_poll_missing_field_in_root(mocker):
    """ Unit test
    Given
        - An incident without the field named 'field_name' in the root
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script returns a false value
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_without_field])
    args = {
        'field': 'field_name',
    }

    result = poll_field(args)

    assert result.readable_output in "The field does not exist."
    assert result.outputs['exists'] is False


# ---------- Incident with customFields entry -------------------


def test_poll_field_from_custom_fields_with_regex_success(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in the 'CustomFields' entry
        - The regex sent is matching the field value
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_custom_fields])
    args = {
        'field': 'field_name',
        'regex': 'Test',
    }

    result = poll_field(args)

    assert result.readable_output in "The field exists."
    assert result.outputs['exists'] is True


def test_poll_field_from_custom_fields_with_regex_failure(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in the 'CustomFields' entry
        - The regex sent does not match the field value
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script returns a false value
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_custom_fields])
    args = {
        'field': 'field_name',
        'regex': 'NOT',
    }

    result = poll_field(args)

    assert result.readable_output in "The field does not exist."
    assert result.outputs['exists'] is False


def test_poll_field_from_custom_fields_without_regex_success(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' with value 'Test' in the 'CustomFields' entry
        - No regex argument sent to the command
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_contains_field_in_custom_fields])
    args = {
        'field': 'field_name',
    }

    result = poll_field(args)

    assert result.readable_output in "The field exists."
    assert result.outputs['exists'] is True


def test_poll_missing_field_in_custom_fields(mocker):
    """ Unit test
    Given
        - An incident with the field named 'field_name' in 'CustomFields' entry with an empty value
        - No regex argument sent to the command
    When
        - mock the server response to demisto.incidents().
    Then
        Validate the script finds the field
    """
    mocker.patch.object(demisto, 'incidents', return_value=[incident_with_empty_field_in_custom_fields])
    args = {
        'field': 'field_name',
    }

    result = poll_field(args)

    assert result.readable_output in "The field does not exist."
    assert result.outputs['exists'] is False

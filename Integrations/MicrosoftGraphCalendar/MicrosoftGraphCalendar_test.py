from .MicrosoftGraphCalendar import *


def test_epoch_seconds():
    integer = epoch_seconds()
    assert isinstance(integer, int)


def test_camel_case_to_readable():
    assert camel_case_to_readable('id') == 'ID'
    assert camel_case_to_readable('createdDateTime') == 'Created Date Time'


def test_parse_outputs():
    outputs = {
        '@odata.context': 'a',
        'classification': 'myclass',
        'securityEnabled': 'true'
    }

    parsed_readable, parsed_outputs = parse_calendar(outputs)

    expected_readable = {
        'Classification': 'myclass',
        'Security Enabled': 'true'
    }
    expected_outputs = {
        'Classification': 'myclass',
        'SecurityEnabled': 'true'
    }
    assert parsed_readable == expected_readable
    assert parsed_outputs == expected_outputs


from SearchIncidents import *
import pytest

data_test_check_if_found_incident = [
    ([], 'failed to get incidents from demisto.\nGot: []'),
    (None, 'failed to get incidents from demisto.\nGot: None'),
    ('', 'failed to get incidents from demisto.\nGot: '),
    ([{'Contents': {'data': None}}], 'Incidents not found.'),
    ([{'Contents': {'data': 'test'}}], None),
    ([{'Contents': {'test': 'test'}}], {'test': 'test'}),
]


@pytest.mark.parametrize('_input, expected_output', data_test_check_if_found_incident)
def test_check_if_found_incident(_input, expected_output):
    output = str(None)
    try:
        check_if_found_incident(_input)
    except DemistoException as error:
        output = str(error)
    assert output == str(expected_output), f'check_if_found_incident({_input}) returns: {output}. expected: {expected_output}'


data_test_is_valid_args = [
    ('\\\n', False),
    ('\\s', False),
    ('\\n', True),
    ('\\t', True),
    ('\\\\', True),
    ('\\"', True),
    ('\\r', True),
    ('\\7', True),
    ('\\\'', True),
]


@pytest.mark.parametrize('_input, expected_output', data_test_is_valid_args)
def test_is_valid_args(_input, expected_output):
    try:
        output = is_valid_args({'test': _input})
    except DemistoException:
        output = False

    assert output == expected_output, f'is_valid_args({_input}) returns: {output}. expected: {expected_output}'

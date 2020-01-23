from SearchIncidentsv2 import *
import pytest

data_test_errors_handel = [
    ([], 'failed to get incidents from demisto got []'),
    (None, 'failed to get incidents from demisto got None'),
    ('', 'failed to get incidents from demisto got '),
    ([{'Contents': {'data': None}}], 'Incidents not found.'),
    ([{'Contents': {'data': 'test'}}], None),
    ([{'Contents': {'test': 'test'}}], {'test': 'test'}),
]


@pytest.mark.parametrize('_input, expected_output', data_test_errors_handel)
def test_errors_handel(_input, expected_output):
    output = errors_handel(_input)
    assert output == expected_output, f'errors_handel({_input}) returns: {output}. expected: {expected_output}'


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
    except SystemExit as system_exit:
        output = system_exit.code == 1

    assert output == expected_output, f'is_valid_args({_input}) returns: {output}. expected: {expected_output}'

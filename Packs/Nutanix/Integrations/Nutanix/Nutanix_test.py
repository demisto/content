"""Nutanix Integration for Cortex XSOAR - Unit Tests file"""

import io
import json

import pytest

from CommonServerPython import DemistoException
from Nutanix import MINIMUM_LIMIT_VALUE
from Nutanix import MINIMUM_PAGE_VALUE
from Nutanix import TIME_FORMAT


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('args, argument_name, minimum, maximum, expected',
                         [({'limit': 5}, 'limit', None, None, 5),
                          ({}, 'limit', None, None, None),
                          ({'limit': 1000}, 'limit', 1000, 1000, 1000)
                          ])
def test_get_and_validate_int_argument_valid_arguments(args, argument_name, minimum, maximum, expected):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as number.
     - Minimum possible value for argument.
     - Maximum possible value for argument.

    When:
     - Case a: Argument exists, no minimum and maximum specified.
     - Case b: Argument does not exist, no minimum and maximum specified.
     - Case c: Argument exist, minimum and maximum specified.

    Then:
     - Case a: Ensure that limit is returned (5).
     - Case b: Ensure that None is returned (limit argument does not exist).
     - Case c: Ensure that limit is returned.
    """
    from Nutanix import get_and_validate_int_argument

    assert (get_and_validate_int_argument(args, argument_name, minimum, maximum)) == expected


@pytest.mark.parametrize('args, argument_name, minimum, maximum, expected_error_message',
                         [({'limit': 5}, 'limit', 6, None, 'limit should be equal or higher than 6'),
                          ({'limit': 5}, 'limit', None, 4, 'limit should be equal or less than 4'),
                          ])
def test_get_and_validate_int_argument_invalid_arguments(args, argument_name, minimum, maximum, expected_error_message):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as number.
     - Minimum possible value for argument.
     - Maximum possible value for argument.

    When:
     - Case a: Argument exists, minimum is higher than argument value.
     - Case b: Argument exists, maximum is lower than argument value.

    Then:
     - Case a: Ensure that DemistoException is thrown with error message which indicates that value is below minimum.
     - Case b: Ensure that DemistoException is thrown with error message which indicates that value is higher
       than maximum.
    """
    from Nutanix import get_and_validate_int_argument

    with pytest.raises(DemistoException, match=expected_error_message):
        get_and_validate_int_argument(args, argument_name, minimum, maximum)


@pytest.mark.parametrize('args, expected',
                         [({'page': MINIMUM_PAGE_VALUE, 'limit': MINIMUM_LIMIT_VALUE}, MINIMUM_PAGE_VALUE),
                          ({}, None)
                          ])
def test_get_page_argument_valid_arguments_success(args, expected):
    """
    Given:
     - Demisto arguments.
     - Expected return value for page argument.

    When:
     - Case a: Page exists, limit exists.
     - Case b: Page does not exist.

    Then:
     - Case a: Ensure that page value is returned.
     - Case b: Ensure that None is returned.
    """
    from Nutanix import get_page_argument

    assert (get_page_argument(args)) == expected


def test_get_page_argument_page_exists_limit_does_not():
    """
    Given:
     - Demisto arguments.

    When:
     - Where page argument exists, and limit argument does not exist.

    Then:
     - Ensure that DemistoException is thrown with error message which indicates that limit argument is missing.
    """
    from Nutanix import get_page_argument

    with pytest.raises(DemistoException, match='Page argument cannot be specified without limit argument'):
        get_page_argument({'page': MINIMUM_PAGE_VALUE})


@pytest.mark.parametrize('args, argument_name, expected',
                         [({'resolved': 'true'}, 'resolved', True),
                          ({'resolved': 'false'}, 'resolved', True),
                          ({}, 'resolved', None),
                          ])
def test_get_optional_boolean_param_valid(args, argument_name, expected):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as boolean.

    When:
     - Case a: Argument exists, and is true.
     - Case b: Argument exists, and is false.
     - Case b: Argument does not exist.

    Then:
     - Case a: Ensure that True is returned.
     - Case b: Ensure that False is returned.
     - Case c: Ensure that None is returned.
    """
    from Nutanix import get_optional_boolean_param
    assert (get_optional_boolean_param(args, argument_name)) == expected


@pytest.mark.parametrize('args, argument_name, expected_error_message',
                         [({'resolved': 'unknown_boolean_value'}, 'resolved',
                           'Argument does not contain a valid boolean-like value'),
                          ({'resolved': 123}, 'resolved',
                           'Argument is neither a string nor a boolean'),
                          ])
def test_get_optional_boolean_param_invalid_argument(args, argument_name, expected_error_message):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as boolean.

    When:
     - Case a: Argument is a non boolean string.
     - Case b: Argument is a number.

    Then:
     - Case a: Ensure that DemistoException is thrown with error message which indicates that string cannot be
       parsed to boolean.
     - Case b: Ensure that DemistoException is thrown with error message which indicates that type of the argument
       is not bool or string that can be parsed.
    """
    from Nutanix import get_optional_boolean_param
    with pytest.raises(DemistoException, match=expected_error_message):
        get_optional_boolean_param(args, argument_name)


@pytest.mark.parametrize('args, time_parameter, expected',
                         [({'start_time': '2020-11-22T16:31:14'}, 'start_time', 1606055474000),
                          ({'start_time': '2020-11-22T16:31:14'}, 'end_time', None),
                          ])
def test_get_optional_time_parameter_valid_time_argument(args, time_parameter, expected):
    """
    Given:
     - Demisto arguments.
     - Argument of type time to extract from Demisto arguments as epoch time.

    When:
     - Case a: Argument exists, and has the expected date format.
     - Case b: Argument does not exist.

    Then:
     - Case a: Ensure that the corresponding epoch time is returned.
     - Case b: Ensure that None is returned.
    """
    from Nutanix import get_optional_time_parameter_as_epoch
    assert (get_optional_time_parameter_as_epoch(args, time_parameter)) == expected


def test_get_optional_time_parameter_invalid_time_argument():
    """
    Given:
     - Demisto arguments.
     - Argument of type time to extract from Demisto arguments as epoch time.

    When:
     - Argument is not formatted in the expected way

    Then:
     - Ensure that DemistoException is thrown with error message which indicates that time string does not match the
       expected time format.
    """
    from Nutanix import get_optional_time_parameter_as_epoch
    with pytest.raises(DemistoException, match=f"""time data 'bla' does not match format '{TIME_FORMAT}'"""):
        (get_optional_time_parameter_as_epoch({'start_time': 'bla'}, 'bla'))

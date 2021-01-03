"""Nutanix Integration for Cortex XSOAR - Unit Tests file"""

import json
import io
import pytest
from Nutanix import MINIMUM_PAGE_VALUE
from Nutanix import MINIMUM_COUNT_VALUE
from CommonServerPython import DemistoException


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('args, argument_name, minimum, maximum, expected',
                         [({'count': 5}, 'count', None, None, 5),
                          ({}, 'count', None, None, None),
                          ({'count': 1000}, 'count', 1000, 1000, 1000)
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
     - Case a: Ensure that count is returned (5).
     - Case b: Ensure that None is returned (count argument does not exist).
     - Case c: Ensure that count is returned.
    """
    from Nutanix import get_and_validate_int_argument

    assert (get_and_validate_int_argument(args, argument_name, minimum, maximum)) == expected


@pytest.mark.parametrize('args, argument_name, minimum, maximum, expected_error_message',
                         [({'count': 5}, 'count', 6, None, 'count should be equal or higher than 6'),
                          ({'count': 5}, 'count', None, 4, 'count should be equal or less than 4'),
                          ])
def test_get_and_validate_int_argument_invalid_arguments(args, argument_name, minimum, maximum, expected_error_message):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as number.
     - Minimum possible value for argument.
     - Maximum possible value for argument.

    When:
     - Case a: Argument exists, minimum is higher than argument value
     - Case b: Argument exists, maximum is lower than argument value

    Then:
     - Case a: Ensure that minimum error_message is returned
     - Case b: Ensure that maximum error_message is returned
    """
    from Nutanix import get_and_validate_int_argument

    with pytest.raises(DemistoException, match=expected_error_message):
        get_and_validate_int_argument(args, argument_name, minimum, maximum)


@pytest.mark.parametrize('args, expected',
                         [({'page': MINIMUM_PAGE_VALUE, 'count': MINIMUM_COUNT_VALUE}, MINIMUM_PAGE_VALUE),
                          ({}, None)
                          ])
def test_get_page_argument_valid_arguments_success(args, expected):
    """
    Given:
     - Demisto arguments.
     - Expected return value for page argument

    When:
     - Case a: Page exists, count exists.
     - Case b: Page does not exist.

    Then:
     - Case a: Ensure that page value is returned
     - Case b: Ensure that None is returned
    """
    from Nutanix import get_page_argument

    assert (get_page_argument(args)) == expected


def test_get_page_argument_page_exists_count_does_not():
    """
    Given:
     - Demisto arguments

    When:
     - Where page argument exists, and count argument does not exist.

    Then:
     - Ensure that exception of missing count argument is thrown
    """
    from Nutanix import get_page_argument

    with pytest.raises(DemistoException, match='Page argument cannot be specified without count argument'):
        get_page_argument({'page': MINIMUM_PAGE_VALUE})

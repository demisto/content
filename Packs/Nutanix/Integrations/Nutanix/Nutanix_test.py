"""Nutanix Integration for Cortex XSOAR - Unit Tests file"""

import io
import json

import pytest
from typing import Dict
from CommonServerPython import DemistoException, CommandResults
from Nutanix import MINIMUM_LIMIT_VALUE
from Nutanix import MINIMUM_PAGE_VALUE
from Nutanix import Client
from Nutanix import fetch_incidents_command, nutanix_hypervisor_hosts_list_command, \
    nutanix_hypervisor_vms_list_command, nutanix_hypervisor_vm_power_status_change_command, \
    nutanix_hypervisor_task_poll_command, nutanix_alerts_list_command, nutanix_alert_acknowledge_command, \
    nutanix_alert_resolve_command, nutanix_alerts_acknowledge_by_filter_command, \
    nutanix_alerts_resolve_by_filter_command

MOCKED_BASE_URL = 'https://prefix:11111/PrismGateway/services/rest/v2.0'
client = Client(base_url=MOCKED_BASE_URL, verify=False, proxy=False, auth=('fake_username', 'fake_password'))


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


command_tests_data = util_load_json('test_data/test_command_data.json')


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
                          ({'resolved': 'false'}, 'resolved', False),
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
    with pytest.raises(ValueError, match=expected_error_message):
        get_optional_boolean_param(args, argument_name)


@pytest.mark.parametrize('args, time_parameter, expected',
                         [({'start_time': '2020-11-22T16:31:14'}, 'start_time', 1606062674000),
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
    with pytest.raises(DemistoException,
                       match='''date format of 'start_time' is not valid. Please enter a date format of YYYY-MM-DDTHH:MM:SS'''):
        (get_optional_time_parameter_as_epoch({'start_time': 'bla'}, 'start_time'))

    commands = {
        'fetch-incidents': fetch_incidents_command,
        'nutanix-hypervisor-hosts-list': nutanix_hypervisor_hosts_list_command,
        'nutanix-hypervisor-vms-list': nutanix_hypervisor_vms_list_command,
        'nutanix-hypervisor-vm-powerstatus-change': nutanix_hypervisor_vm_power_status_change_command,
        'nutanix-hypervisor-task-poll': nutanix_hypervisor_task_poll_command,
        'nutanix-alerts-list': nutanix_alerts_list_command,
        'nutanix-alert-acknowledge': nutanix_alert_acknowledge_command,
        'nutanix-alert-resolve': nutanix_alert_resolve_command,
        'nutanix-alerts-acknowledge-by-filter': nutanix_alerts_acknowledge_by_filter_command,
        'nutanix-alerts-resolve-by-filter': nutanix_alerts_resolve_by_filter_command
    }


@pytest.mark.parametrize('command_function, args, url_suffix, response, expected',
                         [(nutanix_hypervisor_hosts_list_command,
                           command_tests_data['nutanix-hypervisor-hosts-list']['args'],
                           command_tests_data['nutanix-hypervisor-hosts-list']['suffix'],
                           command_tests_data['nutanix-hypervisor-hosts-list']['response'],
                           command_tests_data['nutanix-hypervisor-hosts-list']['expected']),

                          (nutanix_hypervisor_vms_list_command,
                           command_tests_data['nutanix-hypervisor-vms-list']['args'],
                           command_tests_data['nutanix-hypervisor-vms-list']['suffix'],
                           command_tests_data['nutanix-hypervisor-vms-list']['response'],
                           command_tests_data['nutanix-hypervisor-vms-list']['expected']),

                          (nutanix_hypervisor_vm_power_status_change_command,
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['args'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['suffix'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['response'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['expected']),

                          (nutanix_hypervisor_task_poll_command,
                           command_tests_data['nutanix-hypervisor-task-poll']['args'],
                           command_tests_data['nutanix-hypervisor-task-poll']['suffix'],
                           command_tests_data['nutanix-hypervisor-task-poll']['response'],
                           command_tests_data['nutanix-hypervisor-task-poll']['expected']),

                          (nutanix_alerts_list_command,
                           command_tests_data['nutanix-alerts-list']['args'],
                           command_tests_data['nutanix-alerts-list']['suffix'],
                           command_tests_data['nutanix-alerts-list']['response'],
                           command_tests_data['nutanix-alerts-list']['expected']),

                          (nutanix_alert_acknowledge_command,
                           command_tests_data['nutanix-alert-acknowledge']['args'],
                           command_tests_data['nutanix-alert-acknowledge']['suffix'],
                           command_tests_data['nutanix-alert-acknowledge']['response'],
                           command_tests_data['nutanix-alert-acknowledge']['expected']),

                          (nutanix_alert_resolve_command,
                           command_tests_data['nutanix-alert-resolve']['args'],
                           command_tests_data['nutanix-alert-resolve']['suffix'],
                           command_tests_data['nutanix-alert-resolve']['response'],
                           command_tests_data['nutanix-alert-resolve']['expected']),

                          (nutanix_alerts_acknowledge_by_filter_command,
                           command_tests_data['nutanix-alerts-acknowledge-by-filter']['args'],
                           command_tests_data['nutanix-alerts-acknowledge-by-filter']['suffix'],
                           command_tests_data['nutanix-alerts-acknowledge-by-filter']['response'],
                           command_tests_data['nutanix-alerts-acknowledge-by-filter']['expected']),

                          (nutanix_alerts_resolve_by_filter_command,
                           command_tests_data['nutanix-alerts-resolve-by-filter']['args'],
                           command_tests_data['nutanix-alerts-resolve-by-filter']['suffix'],
                           command_tests_data['nutanix-alerts-resolve-by-filter']['response'],
                           command_tests_data['nutanix-alerts-resolve-by-filter']['expected']),
                          ])
def test_command_return_values(requests_mock, command_function, args, url_suffix, response, expected: Dict):
    requests_mock.post(
        f'{MOCKED_BASE_URL}/{url_suffix}',
        json=response
    )
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs')
    )

    assert command_function(client, args) == expected_command_results

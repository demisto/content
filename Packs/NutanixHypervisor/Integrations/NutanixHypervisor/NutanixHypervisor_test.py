"""Nutanix Integration for Cortex XSOAR - Unit Tests file"""

import io
import json
from typing import *

import pytest

from CommonServerPython import DemistoException, CommandResults
from NutanixHypervisor import Client
from NutanixHypervisor import MINIMUM_LIMIT_VALUE
from NutanixHypervisor import MINIMUM_PAGE_VALUE
from NutanixHypervisor import USECS_ENTRIES_MAPPING
from NutanixHypervisor import nutanix_hypervisor_hosts_list_command, \
    nutanix_hypervisor_vms_list_command, nutanix_hypervisor_vm_power_status_change_command, \
    nutanix_hypervisor_task_poll_command, nutanix_alerts_list_command, nutanix_alert_acknowledge_command, \
    nutanix_alert_resolve_command, nutanix_alerts_acknowledge_by_filter_command, \
    nutanix_alerts_resolve_by_filter_command, fetch_incidents_command, get_alert_status_filter, \
    get_optional_boolean_param, get_and_validate_int_argument, get_page_argument, \
    get_optional_time_parameter_as_epoch, update_dict_time_in_usecs_to_iso_entries, convert_epoch_time_to_datetime, \
    create_readable_output

MOCKED_BASE_URL = 'https://prefix:11111/PrismGateway/services/rest/v2.0'
client = Client(base_url=MOCKED_BASE_URL, verify=False, proxy=False, auth=('fake_username', 'fake_password'))


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


command_tests_data = util_load_json('test_data/test_command_data.json')


@pytest.mark.parametrize('args, argument_name, minimum, maximum, default_value, expected',
                         [({'limit': 5}, 'limit', None, None, None, 5),
                          ({}, 'limit', None, None, None, None),
                          ({'limit': 1000}, 'limit', 1000, 1000, None, 1000),
                          ({}, 'limit', 1, 3, 2, 2)
                          ])
def test_get_and_validate_int_argument_valid_arguments(args, argument_name, minimum, maximum, default_value, expected):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as number.
     - Minimum possible value for argument.
     - Maximum possible value for argument.
     - Default value in case argument does not exist.

    When:
     - Case a: Argument exists, no minimum and maximum specified.
     - Case b: Argument does not exist, no minimum and maximum specified, and no default value given.
     - Case c: Argument exist, minimum and maximum specified.
     - Case d: Argument does not exist, default value given and is between maximum and minimum

    Then:
     - Case a: Ensure that limit is returned (5).
     - Case b: Ensure that None is returned (limit argument does not exist).
     - Case c: Ensure that limit is returned.
     - Case d: Ensure that default value is returned.
    """
    assert (get_and_validate_int_argument(args, argument_name, minimum, maximum, default_value)) == expected


@pytest.mark.parametrize('args, argument_name, minimum, maximum, default_value, expected_error_message',
                         [({'limit': 5}, 'limit', 6, None, None, 'limit should be equal or higher than 6'),
                          ({'limit': 5}, 'limit', None, 4, None, 'limit should be equal or less than 4'),
                          ({}, 'limit', 3, 4, 5, 'limit should be equal or less than 4')
                          ])
def test_get_and_validate_int_argument_invalid_arguments(args, argument_name, minimum, maximum, default_value,
                                                         expected_error_message):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as number.
     - Minimum possible value for argument.
     - Maximum possible value for argument.
     - Default value in case argument does not exist.

    When:
     - Case a: Argument exists, minimum is higher than argument value.
     - Case b: Argument exists, maximum is lower than argument value.
     - Case c: Argument does not exist, maximum is lower than argument default value.

    Then:
     - Case a: Ensure that DemistoException is thrown with error message which indicates that value is below minimum.
     - Case b: Ensure that DemistoException is thrown with error message which indicates that value is higher
       than maximum.
    """
    with pytest.raises(DemistoException, match=expected_error_message):
        get_and_validate_int_argument(args, argument_name, minimum, maximum, default_value)


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
    invalid_date_msg = '''date format of 'start_time' is not valid. Please enter a date format of YYYY-MM-DDTHH:MM:SS'''
    with pytest.raises(DemistoException,
                       match=invalid_date_msg):
        (get_optional_time_parameter_as_epoch({'start_time': 'bla'}, 'start_time'))


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

                          (nutanix_alerts_list_command,
                           command_tests_data['nutanix-alerts-list']['args'],
                           command_tests_data['nutanix-alerts-list']['suffix'],
                           command_tests_data['nutanix-alerts-list']['response'],
                           command_tests_data['nutanix-alerts-list']['expected'])
                          ])
def test_commands_get_methods(requests_mock, command_function: Callable[[Client, Dict], CommandResults], args: Dict,
                              url_suffix: str, response: Dict, expected: Dict):
    """
    Given:
     - command function.
     - Demisto arguments.
     - url suffix of the Nutanix service endpoint that the command function will use (needed to mock the request).
     - response returned from Nutanix.
     - expected CommandResults object to be returned from the command function.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    requests_mock.get(
        f'{MOCKED_BASE_URL}/{url_suffix}',
        json=response
    )
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs')
    )
    returned_command_results = command_function(client, args)

    assert returned_command_results.outputs_prefix == expected_command_results.outputs_prefix
    assert returned_command_results.outputs_key_field == expected_command_results.outputs_key_field
    assert returned_command_results.outputs == expected_command_results.outputs


@pytest.mark.parametrize('command_function, args, url_suffix, response, expected',
                         [(nutanix_hypervisor_vm_power_status_change_command,
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['args'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['suffix'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['response'],
                           command_tests_data['nutanix-hypervisor-vm-powerstatus-change']['expected']),

                          (nutanix_hypervisor_task_poll_command,
                           command_tests_data['nutanix-hypervisor-task-poll']['args'],
                           command_tests_data['nutanix-hypervisor-task-poll']['suffix'],
                           command_tests_data['nutanix-hypervisor-task-poll']['response'],
                           command_tests_data['nutanix-hypervisor-task-poll']['expected']),

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
def test_commands_post_methods(requests_mock, command_function: Callable[[Client, Dict], CommandResults], args: Dict,
                               url_suffix: str, response: Dict, expected: Dict):
    """
    Given:
     - command function.
     - Demisto arguments.
     - url suffix of the Nutanix service endpoint that the command function will use (needed to mock the request).
     - response returned from Nutanix.
     - expected CommandResults object to be returned from the command function.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    requests_mock.post(
        f'{MOCKED_BASE_URL}/{url_suffix}',
        json=response
    )
    expected_command_results = CommandResults(
        outputs_prefix=expected.get('outputs_prefix'),
        outputs_key_field=expected.get('outputs_key_field'),
        outputs=expected.get('outputs')
    )
    returned_command_results = command_function(client, args)

    assert returned_command_results.outputs_prefix == expected_command_results.outputs_prefix
    assert returned_command_results.outputs_key_field == expected_command_results.outputs_key_field
    assert returned_command_results.outputs == expected_command_results.outputs


@pytest.mark.parametrize('params, last_run, expected_incidents_raw_json',
                         [({}, {'last_fetch_epoch_time': 1610360118147914},
                           command_tests_data['nutanix-fetch-incidents']['expected']['outputs']),

                          ({}, {'last_fetch_epoch_time': 1610560118147914},
                           [command_tests_data['nutanix-fetch-incidents']['expected']['outputs'][0]])
                          ])
def test_fetch_incidents(requests_mock, params, last_run, expected_incidents_raw_json):
    """
    Given:
     - Demisto parameters.
     - Demisto arguments.
     - Last run of fetch-incidents

    When:
     - Case a: Fetching incidents, not first run. last run fetch time is before both alerts.

     - Case b: Fetching incidents, not first run. last run fetch time is after one alert and before the second alert.

    Then:
     - Case a: Ensure that both alerts are returned as incidents.
               Ensure that last run is set with latest alert time stamp.

     - Case b: Ensure that only latest alert is returned as incident.
               Ensure that last run is set with latest alert time stamp.
    """
    requests_mock.get(
        f'{MOCKED_BASE_URL}/alerts',
        json=command_tests_data['nutanix-fetch-incidents']['response']
    )

    incidents, next_run = fetch_incidents_command(
        client=client,
        params=params,
        last_run=last_run
    )
    incidents_raw_json = [json.loads(incident['rawJSON']) for incident in incidents]
    assert next_run.get('last_fetch_epoch_time') == 1610718924821136
    assert incidents_raw_json == expected_incidents_raw_json


@pytest.mark.parametrize('true_value, false_value, alert_status_filters, expected',
                         [('Resolved', 'Unresolved', ['Resolved', 'Acknowledged'], True),
                          ('Resolved', 'Unresolved', ['Unresolved', 'Acknowledged'], False),
                          ('Resolved', 'Unresolved', ['Acknowledged'], None),
                          ])
def test_get_alert_status_filter_valid_cases(true_value, false_value, alert_status_filters, expected):
    """
    Given:
     - The argument name which corresponds for True value inside 'alert_status_filters' list.
     - The argument name which corresponds for False value inside 'alert_status_filters' list.
     - Alert status filters, contains all the selects for filters done by user.

    When:
     - Case a: User selected argument that corresponds for True value.
     - Case b: User selected argument that corresponds for False value.
     - Case c: User did not select argument that corresponds to true or false value.

    Then:
     - Case a: Ensure True is returned.
     - Case b: Ensure False is returned.
     - Case c: Ensure None is returned.
    """
    assert get_alert_status_filter(true_value, false_value, alert_status_filters) == expected


@pytest.mark.parametrize('true_value, false_value, alert_status_filters',
                         [('Resolved', 'Unresolved', ['Resolved', 'Unresolved']),
                          ('Acknowledged', 'Unacknowledged', ['Acknowledged', 'Unacknowledged']),
                          ('Auto Resolved', 'Not Auto Resolved', ['Auto Resolved', 'Not Auto Resolved'])
                          ])
def test_get_alert_status_filter_invalid_case(true_value, false_value, alert_status_filters):
    """
    Given:
     - The argument name which corresponds for True value inside 'alert_status_filters' list.
     - The argument name which corresponds for False value inside 'alert_status_filters' list.
     - Alert status filters, contains all the selects for filters done by user.

    When:
     - Case a: User selected argument that corresponds for both True and False values.
     - Case b: User selected argument that corresponds for both True and False values.
     - Case c: User selected argument that corresponds for both True and False values.

    Then:
     - Case a: Ensure DemistoException is thrown with the expected message error.
     - Case b: Ensure DemistoException is thrown with the expected message error.
     - Case c: Ensure DemistoException is thrown with the expected message error.
    """
    with pytest.raises(DemistoException,
                       match=f'Invalid alert status filters configurations, only one of {true_value},{false_value} '
                             'can be chosen.'):
        get_alert_status_filter(true_value, false_value, alert_status_filters)


@pytest.mark.parametrize('epoch_time, expected',
                         [(0, None),
                          (None, None),
                          (1600000000000000, '2020-09-13T12:26:40.000000Z')
                          ])
def test_convert_epoch_time_to_datetime_valid_cases(epoch_time, expected):
    """
    Given:
     - Epoch time to be converted to date time string in UTC timezone.

    When:
     - Case a: Epoch time is 0.
     - Case b: Epoch time is not given.
     - Case c: Valid epoch time is given.

    Then:
     - Case a: Ensure None is returned.
     - Case b: Ensure None is returned.
     - Case c: Ensure the corresponding date time string is returned.
    """
    assert convert_epoch_time_to_datetime(epoch_time) == expected


# @pytest.mark.parametrize('epoch_time, expected',
#                          [(0, None),
#                           (None, None),
#                           (1600000000000000, '2020-09-13T12:26:40.000000Z')
#                           ])
# def test_convert_epoch_time_to_datetime_valid_cases(epoch_time, expected):
#     """
#     Given:
#      - Epoch time to be converted to date time string in UTC timezone.
#
#     When:
#      - Case a: Epoch time is 0.
#      - Case b: Epoch time is not given.
#      - Case c: Valid epoch time is given.
#
#     Then:
#      - Case a: Ensure None is returned.
#      - Case b: Ensure None is returned.
#      - Case c: Ensure the corresponding date time string is returned.
#     """
#     assert convert_epoch_time_to_datetime(epoch_time) == expected
#

def test_update_dict_time_in_usecs_to_iso_entries():
    """
    Given:
     - Dict containing entries with epoch time.

    When:
     - Transforming entries with epoch time to entries with iso time for human readable.

    Then:
     - All 'usecs' keys in the dict are replaced with 'iso time' entries with correct iso values.
    """
    tested_dict = {usec_entry: 1600000000000000 for usec_entry in USECS_ENTRIES_MAPPING.keys()}
    tested_dict['host_name'] = 'Nutanix Host'
    update_dict_time_in_usecs_to_iso_entries([tested_dict])
    assert tested_dict['host_name'] == 'Nutanix Host'
    assert all(
        tested_dict.get(iso_entry) == '2020-09-13T12:26:40.000000Z' for iso_entry in USECS_ENTRIES_MAPPING.values())
    assert len(tested_dict) == (1 + len(USECS_ENTRIES_MAPPING))


@pytest.mark.parametrize('outputs, expected_outputs',
                         [([{1: 2, 3: 4, 'a': 'b'}], [{1: 2, 3: 4, 'a': 'b'}]),
                          ([{'a': {2: 3}}], []),
                          ([{1: 2, 3: 4, 'a': {1: 2}}, {'abc': 'def', 'lst': [1, {2: 3}, 3, [4, 5, 6]]}],
                           [{1: 2, 3: 4}, {'abc': 'def', 'lst': [1, 3, [4, 5, 6]]}]),
                          ([{'a': [[[[[[{1: 2}]]]]]]}], [])
                          ])
def test_create_readable_output(outputs, expected_outputs):
    """
    Given:
     - List of outputs.

    When:
     - Creating readable output by given outputs

    Then:
     - All entries with inner dicts and empty values after inner dicts removal are being deleted,
       and every other value is remained as is.
    """
    assert create_readable_output(outputs) == expected_outputs

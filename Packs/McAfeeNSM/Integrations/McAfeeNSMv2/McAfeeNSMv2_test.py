"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
import pytest
from McAfeeNSMv2 import Client


@pytest.fixture
def mcafeensmv2_client():
    return Client(url='url', auth=(), headers={}, proxy=False, verify=False)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_encode_to_base64():
    """
        Given:
            - A string to encode.
        When:
            - Before every command, to be used in the get_session_command.
        Then:
            - An encoded string in base64 is returned.
    """
    from McAfeeNSMv2 import encode_to_base64
    str_to_encode = 'username:password'
    expected = 'dXNlcm5hbWU6cGFzc3dvcmQ='
    result = encode_to_base64(str_to_encode)
    assert expected == result


def test_get_session(mocker, mcafeensmv2_client):
    """
        Given:
            - A string to encode.
        When:
            - Before every command, to be used in the get_session_command.
        Then:
            - An encoded session string in base64 is returned.
    """
    from McAfeeNSMv2 import get_session
    str_to_encode = 'username:password'
    mock_session_result = {
        "session": "ABC3AC9AB39EE322C261B733272FC49F",
        "userId": "1"
    }
    expected_session_id = 'QUJDM0FDOUFCMzlFRTMyMkMyNjFCNzMzMjcyRkM0OUY6MQ=='
    mocker.patch.object(mcafeensmv2_client, 'get_session_request', return_value=mock_session_result)
    result = get_session(mcafeensmv2_client, str_to_encode)
    assert expected_session_id == result


records_list1 = util_load_json('test_data/commands_test_data.json').get('get_list_firewall_policy')[:2]
records_list2 = util_load_json('test_data/commands_test_data.json').get('get_list_firewall_policy')[2:]
records_list2 = records_list2[:2]
test_pagination_params = [(records_list1, 2, 1),
                          (records_list2, 2, 2)]


@pytest.mark.parametrize('expected_records_list, limit, page', test_pagination_params)
def test_pagination(expected_records_list, limit, page):
    """
        Given:
            - A list.
        When:
            - In a call to one of the list commands.
        Then:
            - Returns the wanted records.
    """
    from McAfeeNSMv2 import pagination
    records_list = util_load_json('test_data/commands_test_data.json').get('get_list_firewall_policy')
    wanted_records_list = pagination(records_list, limit, page)
    assert wanted_records_list == expected_records_list


def test_alerts_list_pagination():
    """
        Given:
            - A list of alerts.
        When:
            - In get_alerts command.
        Then:
            - Returns the wanted records.
    """
    from McAfeeNSMv2 import alerts_list_pagination
    records_list = util_load_json('test_data/commands_test_data.json').get('get_alerts_output')
    limit = 1050
    page = 1
    time_period = None
    start_time = None
    end_time = None
    state = None
    search = None
    filter_arg = None
    total_alerts_count = 3
    client = None
    domain_id = 0
    result_list = alerts_list_pagination(records_list, limit, page, time_period, start_time, end_time, state, search,
                                         filter_arg, total_alerts_count, client, domain_id)
    assert records_list == result_list


test_response_cases_params = [('Deny', 'DENY'),
                              ('Stateless Ignore', 'STATELESS_IGNORE')]


@pytest.mark.parametrize('given_response_string, expected_response_string', test_response_cases_params)
def test_response_cases(given_response_string, expected_response_string):
    """
        Given:
            - A string that is the value of response argument.
        When:
            - Using the commands create-firewall-policy and update-firewall-policy.
        Then:
            - Returns correct string for the API call.
    """
    from McAfeeNSMv2 import response_cases
    result = response_cases(given_response_string)
    assert result == expected_response_string


test_rule_object_type_cases_params = [('Endpoint IP V.4', 'HOST_IPV_4', 'up'),
                                      ('Endpoint IP V.4', 'hostipv4', 'low'),
                                      ('Range IP V.4', 'IPV_4_ADDRESS_RANGE', 'up'),
                                      ('Range IP V.4', 'ipv4addressrange', 'low'),
                                      ('Network IP V.4', 'NETWORK_IPV_4', 'up'),
                                      ('Network IP V.4', 'networkipv4', 'low')]


@pytest.mark.parametrize('given_rule_object_type, expected_rule_object_type, case', test_rule_object_type_cases_params)
def test_rule_object_type_cases(given_rule_object_type, expected_rule_object_type, case):
    """
        Given:
            - A string that is the value of rule_object_type arguments.
        When:
            - Using the commands create-firewall-policy, update-firewall-policy and list-domain-rule-object.
        Then:
            - Returns correct string for the API call.
    """
    from McAfeeNSMv2 import rule_object_type_cases
    result = rule_object_type_cases(given_rule_object_type, case)
    assert result == expected_rule_object_type


check_source_and_destination_params = [('1', None, None, None, 'create', 'If you provide at least one of the source '
                                                                         'fields, you must provide all of them.'),
                                       (None, 'HOST_IPV_4', None, None, 'create', 'If you provide at least one of the '
                                                                                  'source fields, you must provide all'
                                                                                  ' of them.'),
                                       (None, None, '1', None, 'create', 'If you provide at least one of the '
                                                                         'destination fields, you must provide all of '
                                                                         'them.'),
                                       (None, None, None, 'IPV_4_ADDRESS_RANGE', 'create', 'If you provide at least one'
                                                                                           ' of the destination fields,'
                                                                                           ' you must provide all of '
                                                                                           'them.'),
                                       (None, None, None, None, 'create', 'You must provide the source fields or '
                                                                          'destination fields or both.')]


@pytest.mark.parametrize('source_rule_object_id, source_rule_object_type, destination_rule_object_id, '
                         'destination_rule_object_type, create_or_update, expected_error',
                         check_source_and_destination_params)
def test_check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                      destination_rule_object_type, create_or_update, expected_error):
    """
        Given:
            - The following args source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                      destination_rule_object_type, create_or_update.
        When:
            - Using the commands create-firewall-policy and update-firewall-policy.
        Then:
            - Check that the user gave the correct arguments.
    """
    from McAfeeNSMv2 import check_source_and_destination
    with pytest.raises(Exception) as e:
        check_source_and_destination(source_rule_object_id, source_rule_object_type, destination_rule_object_id,
                                     destination_rule_object_type, create_or_update)
        assert expected_error == str(e.value)


from_to_list1 = [{
    'FromAddress': '1.1.1.1',
    'ToAddress': '2.2.2.2'
}]
expected_result1 = ('IPv4AddressRange', {
    'IPV4RangeList': from_to_list1
})
expected_result2 = ('HostIPv4', {
    'hostIPv4AddressList': ['1.1.1.1']
})
expected_result3 = ('NETWORK_IPV_4', {
    'networkIPV4List': ['1.1.1.1']
})
create_body_create_rule_params = [('IPV_4_ADDRESS_RANGE', [], 4, from_to_list1, expected_result1),
                                  ('HOST_IPV_4', ['1.1.1.1'], 4, [], expected_result2),
                                  ('NETWORK_IPV_4', ['1.1.1.1'], 4, [], expected_result3)]


@pytest.mark.parametrize('rule_type, address, number, from_to_list, expected_result', create_body_create_rule_params)
def test_create_body_create_rule(rule_type, address, number, from_to_list, expected_result):
    """
        Given:
            - A rule_type, a list of addresses, a number (4 or 6) and a list that contains dictionaries with from and
                do addresses.
        When:
            - Using the commands create-firewall-policy and update-firewall-policy.
        Then:
            - Returns the body for the api request.
    """
    from McAfeeNSMv2 import create_body_create_rule
    result = create_body_create_rule(rule_type, address, number, from_to_list)
    assert result == expected_result


check_args_create_rule_params = [('NETWORK_IPV_4', ['2001:db8::/32'], None, None, 6, 'The version of the IP in '
                                                                                     '"rule_object_type" should match '
                                                                                     'the addresses version.'),
                                 ('NETWORK_IPV_4', None, None, None, 4, 'If the "rule_object_type" is “Endpoint IP V.4”'
                                                                        ' or “Network IP V.4” than the argument '
                                                                        '"address_ip_v.4” must contain a value.'),
                                 ('HOST_IPV_4', ['1.1.1.1'], '1.1.1.1', None, 4, 'If the "rule_object_type" is Endpoint'
                                                                                 ' or Network than from_address and '
                                                                                 'to_addresses parameters should not '
                                                                                 'contain value.'),
                                 ('IPV_4_ADDRESS_RANGE', None, ['1.1.1.1'], None, 4, 'If the "rule_object_type" is '
                                                                                     '“Range IP V.4” than the arguments'
                                                                                     ' “from_address_ip_v.4” and '
                                                                                     '“to_address_ip_v.4” must contain '
                                                                                     'a value.'),
                                 ('IPV_4_ADDRESS_RANGE', ['1.1.1.1'], '1.1.1.1', None, 4, 'If the "rule_object_type" '
                                                                                          'is “Range IP V.4 than the '
                                                                                          'both address_ip_v.4 and '
                                                                                          'address_ip_v.6 should not '
                                                                                          'contain a value')]


@pytest.mark.parametrize('rule_type, address, from_address, to_address, number, expected_error',
                         check_args_create_rule_params)
def test_check_args_create_rule(rule_type, address, from_address, to_address, number, expected_error):
    """
        Given:
            - The following arguments rule_type, address, from_address, to_address, number, expected_error.
        When:
            - Using the command create-firewall-policy.
        Then:
            - Check that the user gave the correct arguments.
    """
    from McAfeeNSMv2 import check_args_create_rule
    with pytest.raises(Exception) as e:
        check_args_create_rule(rule_type, address, from_address, to_address, number)
        assert expected_error == str(e.value)


def test_add_entries_to_alert_list():
    """
        Given:
            - A list of alerts.
        When:
            - In get_alerts command.
        Then:
            - Returns the alerts list with the updated entries.
    """
    from McAfeeNSMv2 import add_entries_to_alert_list
    records_list = util_load_json('test_data/commands_test_data.json').get('get_alerts_output')
    expected_records_list = util_load_json('test_data/commands_test_data.json').get('updated_get_alert_list')
    result_list = add_entries_to_alert_list(records_list)
    assert expected_records_list == result_list


def test_update_sensors_list():
    """
        Given:
            - A list of sensors.
        When:
            - In get_sensors command.
        Then:
            - Returns the sensors list with the updated entries.
    """
    from McAfeeNSMv2 import update_sensors_list
    records_list = util_load_json('test_data/commands_test_data.json').get('get_sensors')
    expected_records_list = util_load_json('test_data/commands_test_data.json').get('expected_sensors_list')
    result_list = update_sensors_list(records_list)
    assert expected_records_list == result_list

import json
import McAfeeNSMv2
import pytest
from McAfeeNSMv2 import Client
from CommonServerPython import *  # noqa: F401


@pytest.fixture
def mcafeensmv2_client():
    return Client(url='url', auth=(), headers={}, proxy=False, verify=False)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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


records_list = util_load_json('test_data/commands_test_data.json').get('get_list_firewall_policy')
records_list2 = records_list[2:]
test_pagination_params = [(records_list[:2], 50, 1, 2),
                          (records_list2[:2], 50, 2, 2),
                          (records_list[:3], 3, None, None)]


@pytest.mark.parametrize('expected_records_list, limit, page, page_size', test_pagination_params)
def test_pagination(expected_records_list, limit, page, page_size):
    """
        Given:
            - A list.
        When:
            - In a call to one of the list commands.
        Then:
            - Returns the wanted records.
    """
    from McAfeeNSMv2 import pagination
    wanted_records_list = pagination(records_list, limit, page, page_size)
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
    records_list = util_load_json('test_data/commands_test_data.json').get('get_alerts_output', {}).get('alertsList')
    page_size = 1050
    page = 1
    time_period = None
    start_time = None
    end_time = None
    state = None
    search = None
    filter_arg = None
    client = None
    domain_id = 0
    limit = 50
    result_list = alerts_list_pagination(records_list, limit, page, page_size, time_period, start_time, end_time, state,
                                         search, filter_arg, client, domain_id)
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
expected_result3 = ('Network_IPV_4', {
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


update_source_destination_object_params = [
    (
        [
            {
                "RuleObjectId": "117",
                "Name": "Range V6 Test",
                "RuleObjectType": "IPV_6_ADDRESS_RANGE",
            }
        ],
        120,
        "HOST_IPV_6",
        [
            {
                "RuleObjectId": "117",
                "Name": "Range V6 Test",
                "RuleObjectType": "IPV_6_ADDRESS_RANGE",
            },
            {"RuleObjectId": 120, "RuleObjectType": "HOST_IPV_6"},
        ],
    ),
    (
        [{"RuleObjectId": "-1", "Name": "Any", "RuleObjectType": None}],
        120,
        "HOST_IPV_6",
        [{"RuleObjectId": 120, "RuleObjectType": "HOST_IPV_6"}],
    ),
]


@pytest.mark.parametrize('obj, rule_object_id, rule_object_type, expected_obj', update_source_destination_object_params)
def test_update_source_destination_object(obj, rule_object_id, rule_object_type, expected_obj):
    """
        Given:
            - A list of Address Object, an id of the new rule, a type of the new rule.
        When:
            - In update_firewall_policy command.
        Then:
            - Returns the updated address object.
    """
    from McAfeeNSMv2 import update_source_destination_object
    result = update_source_destination_object(obj, rule_object_id, rule_object_type)
    assert expected_obj == result


overwrite_source_destination_object_params = [(120, 'HOST_IPV_6', 'Destination', [{'RuleObjectId': 120,
                                                                                   'RuleObjectType': 'HOST_IPV_6'
                                                                                   }]),
                                              (-1, None, 'Destination', [{
                                                  "RuleObjectId": -1,
                                                  "RuleObjectType": None}]),
                                              (None, None, 'Source', [{
                                                  "RuleObjectId": "117",
                                                  "Name": "Range V6 Test",
                                                  "RuleObjectType": "IPV_6_ADDRESS_RANGE"}])]


@pytest.mark.parametrize('rule_object_id, rule_object_type, dest_or_src, expected_obj',
                         overwrite_source_destination_object_params)
def test_overwrite_source_destination_object(rule_object_id, rule_object_type, dest_or_src, expected_obj):
    """
        Given:
            - An id of the new rule, a type of the new rule, a string that represents if it is a source or destination
                object and member_rule_list.
        When:
            - In update_firewall_policy command.
        Then:
            - Returns the updated address object.
    """
    from McAfeeNSMv2 import overwrite_source_destination_object
    member_rule_list = util_load_json('test_data/commands_test_data.json').get('member_rule_list')[0]
    result = overwrite_source_destination_object(rule_object_id, rule_object_type, dest_or_src, member_rule_list)
    assert expected_obj == result


def test_update_filter():
    """
        Given:
            - A filter argument.
        When:
            - In get_alerts_command command.
        Then:
            - Returns the updated filter.
    """
    from McAfeeNSMv2 import update_filter
    filter_arg = 'name:HTTP: IIS 6.0'
    expected_filter_arg = 'name:HTTP  IIS 6 0'
    result = update_filter(filter_arg)
    assert expected_filter_arg == result


def test_get_addresses_from_response():
    """
        Given:
            - A dictionary with the alert details.
        When:
            - In get_alert_details command.
        Then:
            - Returns the updated dictionary with the alert details.
    """
    from McAfeeNSMv2 import get_addresses_from_response
    get_rule_object1 = util_load_json('test_data/commands_test_data.json').get('get_rule_object1')
    get_rule_object2 = util_load_json('test_data/commands_test_data.json').get('get_rule_object2')
    expected_addresses1 = [{'FromAddress': '1.1.1.1', 'ToAddress': '2.2.2.2'}]
    expected_addresses2 = ['3.3.3.3/33', '4.4.4.4/44']
    result1 = get_addresses_from_response(get_rule_object1)
    result2 = get_addresses_from_response(get_rule_object2)
    assert expected_addresses1 == result1
    assert expected_addresses2 == result2


def test_list_domain_firewall_policy_command(mocker, mcafeensmv2_client):
    """
    Given:
        - Domain id, limit to the list, a page. and page_size.

    When:
        - nsm-list-domain-firewall-policy command is executed

    Then:
        - The http request is called with the right arguments,
        and returns a list of the firewall policies in the domain.
    """
    from McAfeeNSMv2 import list_domain_firewall_policy_command
    args = {'domain_id': '0', 'limit': '2'}
    response = util_load_json('test_data/commands_test_data.json').get('list_domain_firewall_policy')
    expected_result = response.get('FirewallPoliciesForDomainResponseList')
    mocker.patch.object(mcafeensmv2_client, 'list_domain_firewall_policy_request', return_value=response)
    result = list_domain_firewall_policy_command(mcafeensmv2_client, args)
    expected_readable_output = '### Firewall Policies List\n' \
                               '|policyId|policyName|domainId|visibleToChild|description|isEditable|policyType|' \
                               'policyVersion|lastModUser|\n' \
                               '|---|---|---|---|---|---|---|---|---|\n' \
                               '| 147 | n | 0 | true | d | true | ADVANCED | 1 | user |\n' \
                               '| 140 | hello | 0 | true | hello policy | true | ADVANCED | 1 | user |\n'
    assert result.readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_get_firewall_policy_command(mocker, mcafeensmv2_client):
    """
    Given:
        - A policy_id.

    When:
        - nsm-get-firewall-policy command is executed

    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from McAfeeNSMv2 import get_firewall_policy_command
    args = {'policy_id': '147'}
    response = util_load_json('test_data/commands_test_data.json').get('get_firewall_policy')
    expected_result = util_load_json('test_data/commands_test_data.json').get('expected_get_firewall_policy')
    mocker.patch.object(mcafeensmv2_client, 'get_firewall_policy_request', return_value=response)
    result = get_firewall_policy_command(mcafeensmv2_client, args)
    expected_readable_output = '### Firewall Policy 147\n' \
                               '|Name|Description|VisibleToChild|IsEditable|PolicyType|PolicyVersion|LastModifiedUser' \
                               '|LastModifiedTime|\n' \
                               '|---|---|---|---|---|---|---|---|\n' \
                               '| n | update policy | true | true | ADVANCED | 1 | user | 2022-12-26 05:37:46 |\n'
    assert result.readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_create_firewall_policy_command(mocker, mcafeensmv2_client):
    """
    Given:
        - A domain id, name, visible_to_child, description, is_editable, policy_type, rule_description, rule_enabled,
            response_param, direction, source_rule_object_id, source_rule_object_type, destination_rule_object_id,
            destination_rule_object_type.
    When:
        - create-firewall-policy command is executed
    Then:
        - The http request is called with the right arguments,
            returns a command result with a success message and a number of the new firewall policy.
    """
    from McAfeeNSMv2 import create_firewall_policy_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    args = {
        'domain': '0',
        'name': 'firewall policy name',
        'description': "some tests",
        'is_editable': 'yes',
        'policy_type': 'Advanced',
        'rule_description': 'some rule',
        'response': 'Scan',
        'direction': 'Either',
        'source_rule_object_id': '1',
        'source_rule_object_type': 'Network IP V.6'
    }
    expected_body = {
        'Name': 'firewall policy name',
        'DomainId': 0,
        'VisibleToChild': True,
        'Description': 'some tests',
        'IsEditable': True,
        'PolicyType': 'ADVANCED',
        'MemberDetails': {
            'MemberRuleList': [
                {
                    'Description': 'some rule',
                    'Enabled': True,
                    'Response': 'SCAN',
                    'Direction': 'EITHER',
                    'SourceAddressObjectList': [{
                        'RuleObjectId': 1,
                        'RuleObjectType': 'NETWORK_IPV_6'
                    }],
                    'DestinationAddressObjectList': [{
                        'RuleObjectId': -1,
                        'RuleObjectType': None
                    }],
                    "SourceUserObjectList": [
                        {
                            "RuleObjectId": '-1',
                            "Name": "Any",
                            "RuleObjectType": "USER"
                        }
                    ],
                    "ServiceObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": None,
                            "ApplicationType": None
                        }
                    ],
                    "ApplicationObjectList": [],
                    "TimeObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Always",
                            "RuleObjectType": None
                        }
                    ]
                }
            ]
        }
    }
    create_firewall_policy_command(mcafeensmv2_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/firewallpolicy',
                                    json_data=expected_body)


def test_update_firewall_policy_command(mocker, mcafeensmv2_client):
    """
    There are three use cases that are being checked in this test.
    1. is_overwrite = false. In this case we want to add the new source rule to the existing one. The result is a list
        of 2 rule object in SourceAddressObjectList.
    2. is_overwrite = true. In this case we want to delete the existing rule object from the firewall policy, and
        replace it with the new one. The result is a list of one rule object in SourceAddressObjectList.
    3. There are no rules before. In this case there is only a source rule, without a destination rule. We want to
        check that when we want to add a new rule to an "empty" rule list, in the list will remain only the new rule,
        without the dummy rule.
    Given:
        - A domain id, name, visible_to_child, description, is_editable, policy_type, rule_description, rule_enabled,
            response_param, direction, source_rule_object_id, source_rule_object_type, destination_rule_object_id,
            destination_rule_object_type, is_overwrite.
    When:
        - update-firewall-policy command is executed
    Then:
        - The http request is called with the right arguments,
            returns a command result with a success message and a number of the updated firewall policy.
    """
    from McAfeeNSMv2 import update_firewall_policy_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    get_response = util_load_json('test_data/commands_test_data.json').get('get_firewall_policy')
    args1 = {
        'policy_id': '147',
        'domain': '0',
        'source_rule_object_id': '12',
        'source_rule_object_type': 'Range IP V.4'
    }
    expected_body1 = {
        "Name": "n",
        "DomainId": "0",
        "VisibleToChild": True,
        "Description": "update policy",
        "IsEditable": True,
        "PolicyType": "ADVANCED",
        "MemberDetails": {
            "MemberRuleList": [
                {
                    "Description": "r",
                    "Enabled": True,
                    "Response": "SCAN",
                    "Direction": "EITHER",
                    "SourceAddressObjectList": [
                        {
                            "Name": "Range V6 Test",
                            "RuleObjectId": "117",
                            "RuleObjectType": "IPV_6_ADDRESS_RANGE",
                        },
                        {
                            "RuleObjectId": 12,
                            "RuleObjectType": "IPV_4_ADDRESS_RANGE"
                        },
                    ],
                    "DestinationAddressObjectList": [
                        {
                            "Name": "Any",
                            "RuleObjectId": "-1",
                            "RuleObjectType": None}
                    ],
                    "SourceUserObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": "USER"}
                    ],
                    "ServiceObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": None,
                            "ApplicationType": None,
                        }
                    ],
                    "ApplicationObjectList": [],
                    "TimeObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Always",
                            "RuleObjectType": None}
                    ],
                }
            ]
        }
    }

    args2 = {
        'policy_id': '147',
        'domain': '0',
        'source_rule_object_id': '12',
        'source_rule_object_type': 'Range IP V.4',
        'is_overwrite': 'true'
    }
    expected_body2 = {
        'Name': 'n',
        'DomainId': '0',
        'VisibleToChild': True,
        'Description': 'update policy',
        'IsEditable': True,
        'PolicyType': 'ADVANCED',
        'MemberDetails': {
            'MemberRuleList': [
                {
                    'Description': 'r',
                    'Enabled': True,
                    'Response': 'SCAN',
                    'Direction': 'EITHER',
                    'SourceAddressObjectList': [
                        {
                            'RuleObjectId': 12,
                            'RuleObjectType': 'IPV_4_ADDRESS_RANGE'
                        }
                    ],
                    'DestinationAddressObjectList': [{
                        'Name': 'Any',
                        'RuleObjectId': '-1',
                        'RuleObjectType': None
                    }],
                    "SourceUserObjectList": [
                        {
                            "RuleObjectId": '-1',
                            "Name": "Any",
                            "RuleObjectType": "USER"
                        }
                    ],
                    "ServiceObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": None,
                            "ApplicationType": None
                        }
                    ],
                    "ApplicationObjectList": [],
                    "TimeObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Always",
                            "RuleObjectType": None
                        }
                    ]
                }
            ]
        }
    }

    args3 = {
        'policy_id': '147',
        'domain': '0',
        'destination_rule_object_id': '12',
        'destination_rule_object_type': 'Range IP V.4'
    }
    expected_body3 = {
        "Name": "n",
        "DomainId": "0",
        "VisibleToChild": True,
        "Description": "update policy",
        "IsEditable": True,
        "PolicyType": "ADVANCED",
        "MemberDetails": {
            "MemberRuleList": [
                {
                    "Description": "r",
                    "Enabled": True,
                    "Response": "SCAN",
                    "Direction": "EITHER",
                    "SourceAddressObjectList": [
                        {
                            "Name": "Range V6 Test",
                            "RuleObjectId": "117",
                            "RuleObjectType": "IPV_6_ADDRESS_RANGE",
                        },
                        {  # this rule obj is here because in case of overwrite = false, the command
                            # update_firewall_policy_command updates the actual response object (happens in the first
                            # check), and it will be used again in the third check. But in the case of
                            # is_overwrite = false, the command creates a new address object and send it to the api
                            # request.
                            "RuleObjectId": 12,
                            "RuleObjectType": "IPV_4_ADDRESS_RANGE"
                        }
                    ],
                    "DestinationAddressObjectList": [
                        {
                            "RuleObjectId": 12,
                            "RuleObjectType": "IPV_4_ADDRESS_RANGE"
                        }
                    ],
                    "SourceUserObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": "USER"}
                    ],
                    "ServiceObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Any",
                            "RuleObjectType": None,
                            "ApplicationType": None,
                        }
                    ],
                    "ApplicationObjectList": [],
                    "TimeObjectList": [
                        {
                            "RuleObjectId": "-1",
                            "Name": "Always",
                            "RuleObjectType": None}
                    ],
                }
            ]
        }
    }

    mocker.patch.object(mcafeensmv2_client, 'get_firewall_policy_request', return_value=get_response)
    update_firewall_policy_command(mcafeensmv2_client, args1)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/firewallpolicy/147',
                                    json_data=expected_body1)
    update_firewall_policy_command(mcafeensmv2_client, args2)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/firewallpolicy/147',
                                    json_data=expected_body2)
    update_firewall_policy_command(mcafeensmv2_client, args3)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/firewallpolicy/147',
                                    json_data=expected_body3)


def test_delete_firewall_policy_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a firewall policy id.
    When:
        - delete-firewall-policy command is executed
    Then:
        - The http request is called with the right arguments, returns a command result with a success message.
    """
    from McAfeeNSMv2 import delete_firewall_policy_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    args = {
        'policy_id': '147'
    }
    delete_firewall_policy_command(mcafeensmv2_client, args)
    http_request.assert_called_with(method='DELETE', url_suffix='/firewallpolicy/147')


def test_list_domain_rule_objects_command(mocker, mcafeensmv2_client):
    """
    Given:
        - Domain id, rule_type, limit to the list, a page and page_size.
    When:
        - nsm-list-domain-rule-object command is executed
    Then:
        - The http request is called with the right arguments, and returns a list with information about the rules
            in the specified domain.
    """
    from McAfeeNSMv2 import list_domain_rule_objects_command
    args = {'domain_id': '0', 'limit': '2'}
    response = util_load_json('test_data/commands_test_data.json').get('list_domain_rule_objects')
    expected_result = response.get('RuleObjDef')
    mocker.patch.object(mcafeensmv2_client, 'list_domain_rule_objects_request', return_value=response)
    mocker.patch.object(McAfeeNSMv2, 'VERSION', 'V9x')
    result = list_domain_rule_objects_command(mcafeensmv2_client, args)
    expected_readable_output = '### List of Rule Objects\n' \
                               '|RuleId|Name|Description|VisibleToChild|RuleType|\n' \
                               '|---|---|---|---|---|\n' \
                               '| 134 | testing |  | false | Endpoint IP V.4 |\n' \
                               '| 129 | rule object | ddd | true | Range IP V.4 |\n'
    assert result.readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_get_rule_object_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a rule_id.
    When:
        - nsm-get-rule-object command is executed
    Then:
        - The http request is called with the right arguments, and returns a Command Result with information
            about the rule.
    """
    from McAfeeNSMv2 import get_rule_object_command
    args = {'rule_id': '113'}
    response = util_load_json('test_data/commands_test_data.json').get('get_rule_object_test')
    expected_result = response.get('RuleObjDef')
    mocker.patch.object(mcafeensmv2_client, 'get_rule_object_request', return_value=response)
    mocker.patch.object(McAfeeNSMv2, 'VERSION', 'V9x')
    result = get_rule_object_command(mcafeensmv2_client, args)
    expected_readable_output = '### Rule Objects 113\n' \
                               '|RuleId|Name|VisibleToChild|RuleType|Addresses|\n' \
                               '|---|---|---|---|---|\n' \
                               '| 113 | Network ip Test | false | Network IP V.4 | 3.3.3.3/33,<br>4.4.4.4/44 |\n'
    assert result.readable_output == expected_readable_output
    assert result.raw_response == expected_result


def test_create_rule_object_command(mocker, mcafeensmv2_client):
    """
    Given:
        - A domain id, rule_object_type, name, visible_to_child, description and matching addresses.
    When:
        - create-rule-object command is executed
    Then:
        - The http request is called with the right arguments,
            returns a command result with a success message and a number of the new rule.
    """
    from McAfeeNSMv2 import create_rule_object_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    args = {
        'domain': '0',
        'rule_object_type': 'Endpoint IP V.6',
        'name': 'new rule',
        'description': "a new rule in the way",
        'address_ip_v.6': '1111:1111:1111:1111:1111:1111:1111:1111'
    }
    expected_body = {
        'RuleObjDef': {
            "domain": 0,
            "ruleobjType": 'HOST_IPV_6',
            "visibleToChild": True,
            "description": 'a new rule in the way',
            "name": 'new rule',
            'HostIPv6': {
                'hostIPv6AddressList': ['1111:1111:1111:1111:1111:1111:1111:1111']
            }
        }
    }
    mocker.patch.object(McAfeeNSMv2, 'VERSION', 'V9x')
    create_rule_object_command(mcafeensmv2_client, args)
    http_request.assert_called_with(method='POST',
                                    url_suffix='/ruleobject',
                                    json_data=expected_body)


def test_update_rule_object_command(mocker, mcafeensmv2_client):
    """
    There are two use cases that are being tested here.
    1. is_overwrite = false. In this case we want to add a new ip address to the existing list. The result is a list
        of 3 addresses in networkIPV4List. Two that was there before and the new address.
    2. is_overwrite = true. In this case we want to delete the existing addresses from the rule object, and
        replace them with the new one. The result is a list of one address in networkIPV4List.
    Given:
        - A domain id, rule_id, description, address_ip_v.4.
    When:
        - update-rule-object command is executed.
    Then:
        - The http request is called with the right arguments,
            returns a command result with a success message and the numcer of the updated rule object.
    """
    from McAfeeNSMv2 import update_rule_object_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    get_response = util_load_json('test_data/commands_test_data.json').get('get_rule_object_test')
    args1 = {
        'rule_id': '113',
        'domain': '0',
        'description': 'updated description',
        'address_ip_v.4': '5.5.5.5/55'
    }
    expected_body1 = {
        'RuleObjDef': {
            "domain": 0,
            "ruleobjType": 'NETWORK_IPV_4',
            "visibleToChild": False,
            "description": 'updated description',
            "name": 'Network ip Test',
            "Network_IPV_4": {
                "networkIPV4List": [
                    "3.3.3.3/33",
                    "4.4.4.4/44",
                    "5.5.5.5/55"
                ]
            }
        }
    }

    args2 = {
        'rule_id': '113',
        'domain': '0',
        'description': 'updated description',
        'address_ip_v.4': '5.5.5.5/55',
        'is_overwrite': 'true'
    }
    expected_body2 = {
        'RuleObjDef': {
            "domain": 0,
            "ruleobjType": 'NETWORK_IPV_4',
            "visibleToChild": False,
            "description": 'updated description',
            "name": 'Network ip Test',
            "Network_IPV_4": {
                "networkIPV4List": [
                    "5.5.5.5/55"
                ]
            }
        }
    }
    mocker.patch.object(McAfeeNSMv2, 'VERSION', 'V9x')
    mocker.patch.object(mcafeensmv2_client, 'get_rule_object_request', return_value=get_response)
    update_rule_object_command(mcafeensmv2_client, args1)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/ruleobject/113',
                                    json_data=expected_body1,
                                    resp_type='response')
    update_rule_object_command(mcafeensmv2_client, args2)
    http_request.assert_called_with(method='PUT',
                                    url_suffix='/ruleobject/113',
                                    json_data=expected_body2,
                                    resp_type='response')


def test_delete_rule_object_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a rule id.
    When:
        - delete-rule-object command is executed
    Then:
        - The http request is called with the right arguments, returns a command result with a success message.
    """
    from McAfeeNSMv2 import delete_rule_object_command
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    args = {
        'rule_id': '147'
    }
    delete_rule_object_command(mcafeensmv2_client, args)
    http_request.assert_called_with(method='DELETE', url_suffix='/ruleobject/147')


def test_get_alerts_command(mocker, mcafeensmv2_client):
    """
    Given:
        - Domain id, limit to the list, time_period, start_time, end_time.
    When:
        - nsm-get-alerts command is executed
    Then:
        - The http request is called with the right arguments, and returns a list with information about the alerts
            in the specified domain.
    """
    from McAfeeNSMv2 import get_alerts_command
    args = {'domain_id': '0', 'time_period': 'CUSTOM', 'start_time': '12/17/2000 14:14',
            'end_time': '12/18/2022 00:26:45'}
    response = util_load_json('test_data/commands_test_data.json').get('get_alerts_output')
    expected_result = util_load_json('test_data/commands_test_data.json').get('updated_get_alert_list')
    mocker.patch.object(mcafeensmv2_client, 'get_alerts_request', return_value=response)
    result = get_alerts_command(mcafeensmv2_client, args)
    expected_readable_output = '### Alerts list. Showing 3 of 3\n' \
                               '|ID|Name|Event Time|Severity|State|Direction|Attack Count|\n' \
                               '|---|---|---|---|---|---|---|\n' \
                               '| 2222222222222222222 | Name 1 | Dec 10, 2022 00:00:0 | High | UnAcknowledged | ' \
                               'Outbound | n/a |\n' \
                               '| 2322222222222222222 | Name 2 | Dec 10, 2022 00:00:0 | Medium | UnAcknowledged | ' \
                               'Outbound | n/a |\n' \
                               '| 3333333333333333333 | Name 3 | Dec 10, 2022 00:00:0 | High | UnAcknowledged | ' \
                               'Inbound | n/a |\n'
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_result


def test_get_attacks_command(mocker, mcafeensmv2_client):
    """
    Given:
        - an attack id.
    When:
        - nsm-get-attacks command is executed
    Then:
        - The http request is called with the right arguments, and returns a Command Result with information about the
            requested attack.
    """
    from McAfeeNSMv2 import get_attacks_command
    args = {'attack_id': '0x00000000'}
    response = util_load_json('test_data/commands_test_data.json').get('get_attacks_command')
    expected_result = util_load_json('test_data/commands_test_data.json').get('expected_get_attacks_list')
    mocker.patch.object(mcafeensmv2_client, 'get_attacks_request', return_value=response)
    result = get_attacks_command(mcafeensmv2_client, args)[0]
    expected_readable_output = '### Attack no.0x00000000\n' \
                               '|ID|Name|Severity|Category|\n' \
                               '|---|---|---|---|\n' \
                               '| 0x00000000 | IP: IP Fragment too Large | 5 | Exploit |\n'
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_result


def test_get_domains_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a domain id.
    When:
        - nsm-get-domains command is executed.
    Then:
        - The http request is called with the right arguments, and returns a Command Result with information about the
            requested domain.
    """
    from McAfeeNSMv2 import get_domains_command
    args = {'domain_id': '0'}
    response = util_load_json('test_data/commands_test_data.json').get('get_domains')
    expected_result = util_load_json('test_data/commands_test_data.json').get('expected_get_domains')
    mocker.patch.object(mcafeensmv2_client, 'get_domains_request', return_value=response)
    result = get_domains_command(mcafeensmv2_client, args)
    expected_readable_output = '### Domain no.0\n' \
                               '|ID|Name|\n' \
                               '|---|---|\n' \
                               '| 0 | My Company |\n'
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_result


def test_get_sensors_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a domain id.
    When:
        - nsm-get-sensors command is executed.
    Then:
        - The http request is called with the right arguments, and returns a Command Result with a list of sensors.
    """
    from McAfeeNSMv2 import get_sensors_command
    args = {'domain_id': '0'}
    response = util_load_json('test_data/commands_test_data.json').get('get_sensors')
    expected_result = util_load_json('test_data/commands_test_data.json').get('expected_sensors_list')
    mocker.patch.object(mcafeensmv2_client, 'get_sensors_request', return_value=response)
    result = get_sensors_command(mcafeensmv2_client, args)
    expected_readable_output = '### Sensors List\n' \
                               '|ID|Name|Description|DomainID|IPSPolicyID|IP Address|\n' \
                               '|---|---|---|---|---|---|\n' \
                               '| 1111 | Name_Device_01 | MCAFEE-NETWORK-SECURITY-PLATFORM | 0 | 0 | 3.3.3.3 |\n'
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_result


def test_get_ips_policies_command(mocker, mcafeensmv2_client):
    """
    Given:
        - a domain id.
    When:
        - nsm-get-ips-policies command is executed.
    Then:
        - The http request is called with the right arguments, and returns a Command Result with a list of ips policies.
    """
    from McAfeeNSMv2 import get_ips_policies_command
    args = {'domain_id': '0'}
    response = util_load_json('test_data/commands_test_data.json').get('get_ips_policies')
    expected_result = util_load_json('test_data/commands_test_data.json').get('expected_get_ips_policies')
    mocker.patch.object(mcafeensmv2_client, 'get_ips_policies_request', return_value=response)
    result = get_ips_policies_command(mcafeensmv2_client, args)
    expected_readable_output = '### IPS Policies List of Domain no.0\n' \
                               '|ID|Name|DomainID|IsEditable|VisibleToChildren|\n' \
                               '|---|---|---|---|---|\n' \
                               '| -1 | Master | 0 | true | true |\n' \
                               '| 0 | Default | 0 | true | true |\n'
    assert result.readable_output == expected_readable_output
    assert result.outputs == expected_result


args1_update_alerts = {
    'state': 'Acknowledged'
}
args2_update_alerts = {
    'state': 'Acknowledged',
    'new_state': 'Unacknowledged',
    'start_time': '12/12/2010 00:00',
}
args3_update_alerts = {
    'state': 'Acknowledged',
    'new_state': 'Unacknowledged',
    'start_time': '12/12/2010 00:00',
    'end_time': '12/12/2022 00:00'
}
update_alerts_command_params = [(args1_update_alerts, 'Error! You must specify a new alert state or a new assignee'),
                                (args2_update_alerts,
                                 'If you provide one of the time parameters, you must provide the other as well'),
                                (args3_update_alerts, 'If you provided a start time or end time, you must assign the '
                                                      'time_period parameter with the value "CUSTOM"')]


@pytest.mark.parametrize('args, expected_error', update_alerts_command_params)
def test_update_alerts_command(args, expected_error, mcafeensmv2_client):
    """
        Given:
            - Args and an expected error.
        When:
            - Using the commands update-alerts.
        Then:
            - Check that the user gave the correct arguments.
    """
    from McAfeeNSMv2 import update_alerts_command
    with pytest.raises(Exception) as e:
        update_alerts_command(mcafeensmv2_client, args)
        assert expected_error == str(e.value)


@pytest.mark.parametrize('input, output', [(777, {'method': 'GET', 'url_suffix': '/domain/9/policyassignments/device/777'}),
                                           (None, {'method': 'GET', 'url_suffix':
                                                   '/domain/9/policyassignments/device'})])
def test_list_device_policy_request__with_and_without_device_id(mocker, mcafeensmv2_client, input, output):
    """
    Given:
        - 1. A device id is given.
        - 2. The device id isn't given.
    When:
        - nsm-list-device-policy command is executed.
    Then:
        - The http request is called with the right arguments:
            1. The url suffix is /domain/{domain_id}/policyassignments/device/{device_id}
            2. The url suffix is /domain/{domain_id}/policyassignments/device}

    """
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    Client.list_device_policy_request(mcafeensmv2_client, domain_id=9, device_id=input)
    assert http_request.call_args[1] == output


@pytest.mark.parametrize('input, output', [({"mock": 777}, {'firewallPolicy': 'mock', 'firewallPortPolicy': 'mock',
                                                            'ipsPolicy': 'mock', 'mock': 777}),
                                           (None, {'firewallPolicy': 'mock', 'firewallPortPolicy': 'mock', 'ipsPolicy': 'mock'})])
def test_assign_interface_policy_request__with_and_without_custom_json(mocker, mcafeensmv2_client, input, output):
    """
    Given:
        - 1. A custom_policy_json is given.
        - 2. A custom_policy_json is not given.
    When:
        - assign_interface_policy_request command is executed.
    Then:
        - The http request is called with the right arguments.
    """
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    Client.assign_interface_policy_request(mcafeensmv2_client, domain_id=9, interface_id=9, custom_policy_json=input,
                                           firewall_policy="mock", firewall_port_policy="mock",
                                           ips_policy="mock")
    assert http_request.call_args[1].get('json_data') == output


@pytest.mark.parametrize('input, output', [(777, '/domain/9/policyassignments/interface/777'),
                                           (None, '/domain/9/policyassignments/interface')])
def test_list_interface_policy_request__with_and_without_intereface_id(mocker, mcafeensmv2_client, input, output):
    """
    Given:
        - 1. A interface id is given.
        - 2. A interface id is not given.
    When:
        - nsm-list_interface_policy_request command is executed.
    Then:
        - The http request is called with the right arguments.
    """
    http_request = mocker.patch.object(mcafeensmv2_client, '_http_request')
    Client.list_interface_policy_request(mcafeensmv2_client, domain_id=9, interface_id=input)
    assert http_request.call_args[1].get('url_suffix') == output


@pytest.mark.parametrize('input, output', [(({"from_to_list": [{"FromAddress": "1.1.1.1", "ToAddress": "2.2.2.2"}],
                                             "rule_type": 'IPV_4_ADDRESS_RANGE', "address": [],
                                              "number": 4, "state": "Enabled"},
                                            ('IPv4AddressRange',
                                            {'IPV4RangeList': [{'FromAddress': '1.1.1.1',
                                                                'ToAddress': '2.2.2.2', 'state': 1}]}))),
                                           (({"from_to_list": [{'FromAddress': None, 'ToAddress': None}],
                                             "rule_type":
                                                 'HOST_IPV_4', "address": ["1.1.1.1"], "number": 4, "state": "Disabled"}),
                                           ('HostIPv4', {'hostIPv4AddressList': [{'value': '1.1.1.1', 'state': 0}]})),
                                           (({"from_to_list": [{'FromAddress': None, 'ToAddress': None, 'state': 1}],
                                             "rule_type": 'NETWORK_IPV_6', "address": ['Network IP V.6'],
                                              "number": 6, "state": "Disabled"}),
                                           ('Network_IPV_6', {'networkIPV6List': [{'value': 'Network IP V.6', 'state': 0}]}))])
def test_create_body_create_rule_for_v10__with_different_arguments(input, output):
    """
    Given:
        - A rule type and other relevant arguments.
    When:
        - create_body_create_rule_for_v10 command is executed.
    Then:
        - The body is created correctly according to the rule type and other given arguments.
    """
    from McAfeeNSMv2 import create_body_create_rule_for_v10
    res = create_body_create_rule_for_v10(from_to_list=input.get("from_to_list"),
                                          rule_type=input.get("rule_type"),
                                          address=input.get("address"), number=input.get("number"),
                                          state=input.get("state"))
    assert res == output


@pytest.mark.parametrize('input, output', [({"rule": "HOST", "from_to_list": []},
                                            ('HostIPv9', {'hostIPv9AddressList': [
                                                {'value': '1234', 'state': 1, 'changedState': 3},
                                                {'value': '789', 'state': 1, 'changedState': 1}]})),
                                           ({"rule": "ADDRESS_RANGE", "from_to_list": [{"mock"}]},
                                            ('IPv9AddressRange', {'IPV9RangeList': [{'mock', 'state', 'changedState'}]})),
                                           ({"rule": "NETWORK", "from_to_list": []},
                                            ('Network_IPV_9', {'networkIPV9List': [
                                                {'value': '1234', 'state': 1, 'changedState': 3},
                                                {'value': '789', 'state': 1, 'changedState': 1}]}))])
def test_create_body_update_rule_for_v10(input, output):
    """
    Given:
        - A rule type and other relevant arguments.
        1. A rule type is HOST. from_to_list is empty.
        2. A rule type is ADDRESS_RANGE. from_to_list is not empty.
        3. A rule type is NETWORK. from_to_list is empty.
    When:
        - create_body_update_rule_for_v10 command is executed.
    Then:
        - The body is created correctly according to the rule type and other given arguments.
    """
    from McAfeeNSMv2 import create_body_update_rule_for_v10
    res = create_body_update_rule_for_v10(rule_type=input.get("rule"),
                                          address=[{"test": "test", "value": "1234"}, "789"], number=9,
                                          from_to_list=input.get("from_to_list"))

    assert res == output


def test_modify_v10_results_to_v9_format():
    """
    Given:
        - Results from a v10 api call, that contains a list of dictionaries under the HostIPv4 key.
    When:
        - modify_v10_results_to_v9_format command is executed.
    Then:
        - The list is modified correctly, and the list of dictionaries is replaced with a list of strings of the address only.
    """
    from McAfeeNSMv2 import modify_v10_results_to_v9_format
    test_input = [{'ruleobjId': '130', 'HostIPv4': {'hostIPv4AddressList': [{'ruleObjectID': 130,
                                                                            'value': '1.1.1.1', 'state': 0,
                                                                             'comment': '', 'userID': 0,
                                                                             'changedState': 0}]}, 'HostIPv6': None}]
    excepted_output = [{'ruleobjId': '130', 'HostIPv4': {'hostIPv4AddressList': ['1.1.1.1']}, 'HostIPv6': None}]
    assert modify_v10_results_to_v9_format(test_input) == excepted_output


@pytest.mark.parametrize('input, output', [({"input_lst": [{'mOCK': '130', 'Hos': "7"}, {'mocER': '130', 'MOCKER': "7"}],
                                             "check_lst": ['mOCK']}, [{'MOCK': '130'}]),
                                           ({"input_lst": [{'mOCK': '130', 'Host': "7"}, {'mocER': '130', 'MOCKER': "7"}]},
                                            [{'MOCK': '130', 'Host': '7'}, {'MocER': '130', 'MOCKER': '7'}])])
def test_capitalize_key_first_letter(input, output):
    """
    Given:
        - A dictionary containing dictionaries.
            - 1. A list of keys to check.
            - 2. A list of keys to check is not given.
    When:
        - capitalize_key_first_letter command is executed.
    Then:
        - The keys of the dictionary are capitalized if they are in the list, if a check list was given.
    """
    from McAfeeNSMv2 import capitalize_key_first_letter
    assert capitalize_key_first_letter(input_lst=input.get("input_lst"), check_lst=input.get("check_lst")) == output


@pytest.mark.parametrize('input, output', [({"domain_id": 0, "device_id": 0},
                                            [{'interfaceId': 'mock'}, {'interfaceId': 'mock'}]),
                                           ({"domain_id": 777, "device_id": 777, "limit": 1}, [{'interfaceId': 'mock'}]),
                                           ({"domain_id": 777, "device_id": 777, "limit": 1, "all_results": True},
                                            [{'interfaceId': 'mock'}, {'interfaceId': 'mock'}])])
def test_list_device_interface_command__with_different_arguments(mocker, input, output, mcafeensmv2_client):
    """
    Given:
        - A domain id, device id.
            - 1. A limit was not given.
            - 2. A limit was given.
            - 3. A limit and all results == True, were given.
    When:
        - nsm-list_device_interface_command command is executed.
    Then:
        - Confirm the output is as expected(number of results, and ID = 0 dose not raise an error).
    """
    from McAfeeNSMv2 import list_device_interface_command
    mocker.patch.object(mcafeensmv2_client, 'list_device_interface_request',
                        return_value={})
    mocker.patch.object(McAfeeNSMv2, 'capitalize_key_first_letter', return_value=[{"interfaceId": "mock"},
                                                                                  {"interfaceId": "mock"}])
    res = list_device_interface_command(client=mcafeensmv2_client, args=input)
    assert res.outputs == output


@pytest.mark.parametrize('input, output', [({"domain_id": 0}, [{'policyId': 'mock'}, {'policyId': 'mock'}]),
                                           ({"domain_id": 777, "limit": 1}, [{'policyId': 'mock'}]),
                                           ({"domain_id": 777, "limit": 1, "all_results": True},
                                            [{'policyId': 'mock'}, {'policyId': 'mock'}])])
def test_list_device_policy_command__with_different_arguments(mocker, input, output, mcafeensmv2_client):
    """
    Given:
        - A domain_id.
            - 1. A limit was not given.
            - 2. A limit was given.
            - 3. A limit and all results == True, were given.
    When:
        - nsm-list_device_policy_command command is executed.
    Then:
        - Confirm the output is as expected(number of results, and ID = 0 dose not raise an error).
    """
    from McAfeeNSMv2 import list_device_policy_command
    mocker.patch.object(mcafeensmv2_client, 'list_device_policy_request',
                        return_value={})
    mocker.patch.object(McAfeeNSMv2, 'capitalize_key_first_letter', return_value=[{"policyId": "mock"}, {"policyId": "mock"}]),
    res = list_device_policy_command(client=mcafeensmv2_client, args=input)
    assert res.outputs == output


@pytest.mark.parametrize('input, output', [({"domain_id": 0}, [{'deviceId': 'mock'}, {'deviceId': 'mock'}]),
                                           ({"domain_id": 777, "limit": 1}, [{'deviceId': 'mock'}]),
                                           ({"domain_id": 777, "limit": 1, "all_results": True},
                                            [{'deviceId': 'mock'}, {'deviceId': 'mock'}])])
def test_list_domain_device_command_with_different_arguments(mocker, mcafeensmv2_client, input, output):
    """
    Given:
        - A domain id.
            - 1. A limit was not given.
            - 2. A limit was given.
            - 3. A limit and all results == True, were given.
    When:
        - nsm-list_domain_device_command command is executed.
    Then:
        - Confirm the output is as expected (number of results, and ID = 0 dose not raise an error).
    """
    from McAfeeNSMv2 import list_domain_device_command
    mocker.patch.object(mcafeensmv2_client, 'list_domain_device_request',
                        return_value={})
    mocker.patch.object(McAfeeNSMv2, 'capitalize_key_first_letter', return_value=[{"deviceId": "mock"}, {"deviceId": "mock"}])
    res = list_domain_device_command(client=mcafeensmv2_client, args=input)
    assert res.outputs == output


@pytest.mark.parametrize('input, output', [({"interface_id": None,
                                             "return_value": [{"policyId": "mock"}, {"policyId": "mock"}]},
                                            [{'policyId': 'mock'}, {'policyId': 'mock'}]),
                                           ({"interface_id": 777,
                                             "return_value": [{"policyId": "mock"}, {"policyId": "mock"}]},
                                            [{'policyId': 'mock'}, {'policyId': 'mock'}])])
def test_list_interface_policy_command__with_multiple_different_arguments(mocker, mcafeensmv2_client, input, output):
    """
    Given:
        - A domain id.
            - 1. A limit was not given.
            - 2. A limit was given.
            - 3. A limit and all results == True, were given.
    When:
        - nsm-list_interface_policy_command command is executed.
    Then:
        - Confirm the output is as expected(number of results, and ID = 0 dose not raise an error ).
    """
    from McAfeeNSMv2 import list_interface_policy_command
    mocker.patch.object(mcafeensmv2_client, 'list_interface_policy_request',
                        return_value={})
    mocker.patch.object(McAfeeNSMv2, 'capitalize_key_first_letter', return_value=input.get("return_value"))
    res = list_interface_policy_command(client=mcafeensmv2_client,
                                        args={"domain_id": 0, "interface_id": input.get("interface_id"),
                                              "limit": 1, "all_results": True})
    assert res.outputs == output


def test_get_device_configuration_command(mocker, mcafeensmv2_client):
    """
    Given:
        - A device id.
    When:
        - nsm-get_device_configuration_command command is executed.
    Then:
        - Confirm the output is as expected, and ID = 0 dose not raise an error.
    """
    from McAfeeNSMv2 import get_device_configuration_command
    mocker.patch.object(mcafeensmv2_client, 'get_device_configuration_request',
                        return_value={"deviceConfiguration": {"deviceConfigurationId": "mock"}})
    res = get_device_configuration_command(client=mcafeensmv2_client, args={"device_id": 0})
    assert res.outputs == {'DeviceConfiguration': {'deviceConfigurationId': 'mock'}}


def test_deploy_device_configuration_command__missing_arguments(mocker, mcafeensmv2_client):
    """
    Given:
        - A device id withot arguments to deploy.
    When:
        - deploy_device_configuration_command command is executed.
    Then:
        - Confirm the output is as expected(error message).
    """
    from McAfeeNSMv2 import deploy_device_configuration_command
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    with pytest.raises(DemistoException) as e:
        deploy_device_configuration_command(client=mcafeensmv2_client, args={"device_id": 777})
    assert e.value.message == "Please provide at least one argument to deploy."


@pytest.mark.parametrize('input, output', [(([0], "tets"), "tets\n\nChecking again in 30 seconds..."),
                                           (([1], "TEST"), 'The device configuration has been deployed successfully.')])
def test_deploy_device_configuration_command(mocker, mcafeensmv2_client, input, output):
    """

    Given:
        - A fail_or_seccess_list, 1 or 0, and a message.
            - 1. A pending status list = 0
            - 2. A success status list = 1
    When:
        - deploy_device_configuration_command command is executed.
    Then:
        - Confirm the readable output is as expected.
    """
    from McAfeeNSMv2 import deploy_device_configuration_command
    mocker.patch.object(McAfeeNSMv2, 'check_required_arg', return_value=5)
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported', return_value=None)
    mocker.patch.object(mcafeensmv2_client, 'deploy_device_configuration_request',
                        return_value={"RequestId": "123"})
    mocker.patch.object(mcafeensmv2_client, 'check_deploy_device_configuration_request_status',
                        return_value=input)
    mocker.patch.object(McAfeeNSMv2, 'deploy_polling_message', return_value=input)
    res = deploy_device_configuration_command(args={"device_id": 0,
                                                    "interval_in_seconds": 50,
                                                    "push_botnet": False,
                                                    "push_configuration_signature_set": "true",
                                                    "push_gam_updates": False,
                                                    "push_ssl_key": False
                                                    }, client=mcafeensmv2_client)
    assert res.readable_output == output


@pytest.mark.parametrize('input, output', [("m", 1),
                                           ("x", 0)])
def test_flatten_and_capitalize(mocker, input, output):
    """
    Given:
        - A dictionary with inner dictionaries.
        1. A key of the inner dictionary to capitalize exists in the main dict.
        2. A key of the inner dictionary to capitalize not exists in the main dict.
    When:
        - flatten_and_capitalize function is executed.
    Then:
        - Confirm the capitalize_key_first_letter function is called as expected.
    """
    from McAfeeNSMv2 import flatten_and_capitalize
    # from McAfeeNSMv2 import capitalize_key_first_letter
    my_mocker = mocker.patch.object(McAfeeNSMv2, 'capitalize_key_first_letter', return_value=[{"bla": "bla"}])
    flatten_and_capitalize(main_dict={"a": "l", "m": {"b": "cD", "eF": "gH", }}, inner_dict_key=input)
    assert my_mocker.call_count == output


def test_check_required_arg__with_None():
    """
    Given:
        - A required argument with a None value.
    When:
        - check_required_arg function is executed.
    Then:
        - Confirm the output is as expected. (error message)
    """
    from McAfeeNSMv2 import check_required_arg
    with pytest.raises(DemistoException) as e:
        check_required_arg(arg_name="test", arg_value=None)
    assert e.value.message == 'Please provide a test argument.'


def test_check_required_arg__with_value_0():
    """
    Given:
        - A required argument with an 0 as a value.
    When:
        - check_required_arg function is executed.
    Then:
        - Confirm the output is as expected.
    """
    from McAfeeNSMv2 import check_required_arg
    assert check_required_arg(arg_name="test", arg_value=0) == 0


@pytest.mark.parametrize('input, output', [({"sigsetConfigPercentageComplete": "0", "sigsetConfigStatusMessage": "mock"},
                                            ([0], "\nThe current percentage of deployment for 'push_configuration_signature_set' is: 0%\n                \nAnd the current message is: mock\n")),  # noqa: E501
                                            ({"sigsetConfigPercentageComplete": 100,
                                              "sigsetConfigStatusMessage": "DOWNLOAD COMPLETE"}, ([1], ''))])
def test_deploy_polling_message(input, output):
    """
    Given:
        - A percentage complete and a status message.
        1. A pending status message.
        2. A success status message.
    When:
        - deploy_polling_message function is executed.
    Then:
        - Confirm the output is as expected.
    """
    from McAfeeNSMv2 import deploy_polling_message
    res = deploy_polling_message(status=input, args={"device_id": 0,
                                                     "interval_in_seconds": 50,
                                                     "push_botnet": False,
                                                     "push_configuration_signature_set": "true",
                                                     "push_gam_updates": False,
                                                     "push_ssl_key": False
                                                     })
    assert res[1] == output[1]
    assert res[0] == output[0]

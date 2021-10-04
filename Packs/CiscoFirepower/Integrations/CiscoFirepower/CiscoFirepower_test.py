import pytest
from CiscoFirepower import switch_list_to_list_counter, raw_response_to_context_list, raw_response_to_context_rules, \
    raw_response_to_context_network_groups, raw_response_to_context_policy_assignment, \
    raw_response_to_context_access_policy

INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER = [
    ({'name': 'n', 'type': 't', 'devices': [1, 2, 3]}, {'name': 'n', 'type': 't', 'devices': 3}),
    ({'name': 'n', 'type': 't', 'devices': {'new': [1, 2], 'old': [1, 2]}}, {'name': 'n', 'type': 't', 'devices': 4}),
    ({'name': 'n', 'type': 't', 'devices': {'new': 1, 'old': [1, 2]}}, {'name': 'n', 'type': 't', 'devices': 3}),
    ({'name': 'n', 'type': 't', 'devices': {'new': 'my new'}}, {'name': 'n', 'type': 't', 'devices': 1})
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_LIST = [
    (
        {"id": "123", "metadata": {"domain": {"id": "456"}}, "name": "home", "type": "URLCategory"},
        ['id', 'name'],
        {"ID": "123", "Name": "home"},
    ),
    (
        {
            "id": "abba9b63-bb10-4729-b901-2e2aa0f02064",
            "links": {
                "self": "https:/api/fmc_config/v1/domai"
            },
            "metadata": {
                "domain": {
                    "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
                    "name": "Global",
                    "type": "Domain"
                },
                "lastUser": {
                    "id": "68d03c42-d9bd-11dc-89f2-b7961d42c462",
                    "name": "admin",
                    "type": "user"
                },
                "readOnly": {
                    "state": 'false'
                },
                "timestamp": '1575996253'
            },
            "name": "Child Abuse Content",
            "type": "URLCategory"
        },
        ['id', 'name'],
        {"ID": "abba9b63-bb10-4729-b901-2e2aa0f02064",
         "Name": "Child Abuse Content"},
    ),
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_NETWORK_GROUPS = [
    (
        {
            "description": " ",
            "id": "69fa2a3a-4487-4e3c-816f-4098f684826e",
            "links": {"self": "https:/api/fmc_config/v1/domain/e276abec-e0f2-11e3"},
            "literals": [{"type": "Network", "value": "0.0.0.0/0"}, {"type": "Host", "value": "::/0"}],
            "metadata": {
                "domain": {
                    "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
                    "name": "Global",
                    "type": "Domain"
                },
                "lastUser": {
                    "name": "admin"
                },
                "readOnly": {
                    "reason": "SYSTEM",
                    "state": 'true'
                },
                "timestamp": '1521658703283'
            },
            "name": "any",
            "overridable": 'false',
            "type": "NetworkGroup"
        },
        {
            "Name": "any",
            "ID": "69fa2a3a-4487-4e3c-816f-4098f684826e",
            "Overridable": 'false',
            "Description": " ",
            "Objects": [],
            "Addresses": [
                {
                    "Value": "0.0.0.0/0",
                    "Type": "Network"
                },
                {
                    "Value": "::/0",
                    "Type": "Host"
                }
            ]
        }
    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_POLICY_ASSIGNMENT = [
    (
        {
            "id": "000C29A8-BA3B-0ed3-0000-124554069675",
            "links": {"self": "https:/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f"},
            "name": "BPS-Testing",
            "policy": {
                "id": "000C29A8-BA3B-0ed3-0000-124554069675",
                "name": "BPS-Testing",
                "type": "AccessPolicy"
            },
            "targets": [
                {
                    "id": "43e032dc-07c5-11ea-b83d-d5fdc079bf65",
                    "keepLocalEvents": 'false',
                    "name": "FTD_10.8.49.209",
                    "type": "Device"
                }
            ],
            "type": "PolicyAssignment"
        },
        {
            "ID": "000C29A8-BA3B-0ed3-0000-124554069675",
            "Name": "BPS-Testing",
            "PolicyID": "000C29A8-BA3B-0ed3-0000-124554069675",
            "PolicyName": "BPS-Testing",
            "PolicyDescription": "",
            "Targets": [
                {
                    "ID": "43e032dc-07c5-11ea-b83d-d5fdc079bf65",
                    "Name": "FTD_10.8.49.209",
                    "Type": "Device"
                }
            ]
        },

    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_ACCESS_POLICY = [
    (
        {
            "defaultAction": {
                "action": "BLOCK",
                "id": "000C29A8-BA3B-0ed3-0000-000268443687",
                "logBegin": 'false',
                "logEnd": 'false',
                "sendEventsToFMC": 'false',
                "type": "AccessPolicyDefaultAction"
            },
            "id": "000C29A8-BA3B-0ed3-0000-124554069675",
            "links": {
                "self": "https:/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy"
            },
            "metadata": {
                "domain": {
                    "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
                    "name": "Global",
                    "type": "Domain"
                },
                "inherit": 'false'
            },
            "name": "BPS-Testing",
            "prefilterPolicySetting": {
                "id": "4897c8f4-e211-4661-b0a4-25b0826cded9",
                "name": "Default Prefilter Policy",
                "type": "PrefilterPolicy"
            },
            "rules": {
                "links": {
                    "self": "https:/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy"
                },
                "refType": "list",
                "type": "AccessRule"
            },
            "type": "AccessPolicy"
        },
        {
            "DefaultActionID": "000C29A8-BA3B-0ed3-0000-000268443687",
            "ID": "000C29A8-BA3B-0ed3-0000-124554069675",
            "Name": "BPS-Testing"
        }
    )
]

INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_RULS = [
    (
        {
            "action": "BLOCK",
            "destinationNetworks": {
                "literals": [
                    {
                        "type": "Host",
                        "value": "8.8.8.2"
                    },
                    {
                        "type": "Host",
                        "value": "4.4.4.8"
                    }
                ]
            },
            "enableSyslog": 'false',
            "enabled": 'false',
            "id": "000C29A8-BA3B-0ed3-0000-000268443653",
            "links": {
                "self": "https:/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy"
            },
            "logBegin": 'false',
            "logEnd": 'false',
            "logFiles": 'false',
            "metadata": {
                "accessPolicy": {
                    "id": "000C29A8-BA3B-0ed3-0000-085899346038",
                    "name": "Performance Test Policy without AMP",
                    "type": "AccessPolicy"
                },
                "category": "--Undefined--",
                "domain": {
                    "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
                    "name": "Global",
                    "type": "Domain"
                },
                "ruleIndex": '5',
                "section": "Default",
                "timestamp": '1582462113800'
            },
            "name": "newUpdateTest",
            "sendEventsToFMC": 'false',
            "sourceNetworks": {
                "literals": [
                    {
                        "type": "Host",
                        "value": "10.0.0.1"
                    },
                    {
                        "type": "Host",
                        "value": "8.8.8.6"
                    }
                ]
            },
            "type": "AccessRule",
            "urls": {
                "literals": [
                    {
                        "type": "Url",
                        "url": "google.com"
                    },
                    {
                        "type": "Url",
                        "url": "google.co.il"
                    }
                ]
            },
            "variableSet": {
                "id": "76fa83ea-c972-11e2-8be8-8e45bb1343c0",
                "name": "Default-Set",
                "type": "VariableSet"
            },
            "vlanTags": {}
        },
        {
            'Action': 'BLOCK',
            'Applications': [],
            'Category': '--Undefined--',
            'DestinationNetworks': {'Addresses': [{'Type': 'Host', 'Value': '8.8.8.2'},
                                                  {'Type': 'Host', 'Value': '4.4.4.8'}], 'Objects': []},
            'DestinationPorts': {'Addresses': [], 'Objects': []},
            'DestinationZones': {'Objects': []},
            'Enabled': 'false',
            'ID': '000C29A8-BA3B-0ed3-0000-000268443653',
            'Name': 'newUpdateTest',
            'RuleIndex': '5',
            'Section': 'Default',
            'SendEventsToFMC': 'false',
            'SourceNetworks': {
                'Addresses': [{'Type': 'Host', 'Value': '10.0.0.1'}, {'Type': 'Host', 'Value': '8.8.8.6'}],
                'Objects': []},
            'SourcePorts': {'Addresses': [], 'Objects': []},
            'SourceSecurityGroupTags': {'Objects': []},
            'SourceZones': {'Objects': []},
            'Urls': {'Addresses': [{'URL': 'google.com'}, {'URL': 'google.co.il'}], 'Objects': []},
            'VlanTags': {'Numbers': [], 'Objects': []}
        }
    )
]

""" TESTS FUNCTION """


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_SWITCH_LIST_TO_LIST_COUNTER)
def test_switch_list_to_list_counter(list_input, list_output):
    result = switch_list_to_list_counter(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_to_output, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_LIST)
def test_raw_response_to_context_list(list_to_output, list_input, list_output):
    result = raw_response_to_context_list(list_to_output, list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_NETWORK_GROUPS)
def test_raw_response_to_context_network_groups(list_input, list_output):
    result = raw_response_to_context_network_groups(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_POLICY_ASSIGNMENT)
def test_raw_response_to_context_policy_assignment(list_input, list_output):
    result = raw_response_to_context_policy_assignment(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_ACCESS_POLICY)
def test_raw_response_to_context_access_policy(list_input, list_output):
    result = raw_response_to_context_access_policy(list_input)
    assert list_output == result


@pytest.mark.parametrize('list_input, list_output', INPUT_TEST_RAW_RESPONSE_TO_CONTEXT_RULS)
def test_raw_response_to_context_ruls(list_input, list_output):
    result = raw_response_to_context_rules(list_input)
    assert list_output == result

import pytest
from Exabeam import Client, contents_append_notable_user_info, contents_user_info, get_peer_groups, \
    get_user_labels, get_watchlist, get_asset_data, get_session_info_by_id, get_rules_model_definition, \
    parse_context_table_records_list
from test_data.response_constants import RESPONSE_PEER_GROUPS, RESPONSE_USER_LABELS, RESPONSE_WATCHLISTS, \
    RESPONSE_ASSET_DATA, RESPONSE_SESSION_INFO, RESPONSE_MODEL_DATA
from test_data.result_constants import EXPECTED_PEER_GROUPS, EXPECTED_USER_LABELS, EXPECTED_WATCHLISTS, \
    EXPECTED_ASSET_DATA, EXPECTED_SESSION_INFO, EXPECTED_MODEL_DATA


def test_contents_append_notable_user_info():
    contents = []
    user_ = {
        "username": 'my_username',
        "lastActivityType": 'malicious',
        "labels": 'bad'
    }
    user = {
        "userFullName": 'my_fullname',
        "notableSessionIds": '123',
        "highestRiskSession": 5
    }
    user_info = {
        "riskScore": 3,
        "location": 'lake wanaka',
        "employeeType": 'manager',
        "department": 'my_dept',
        "title": 'my_title'
    }
    outputs = contents_append_notable_user_info(contents, user, user_, user_info)

    expected_outputs = [{
        "UserName": 'my_username',
        "RiskScore": 3,
        "FirstSeen": None,
        "LastSeen": None,
        "LastActivity": 'malicious',
        "Labels": 'bad',
        "UserFullName": 'my_fullname',
        "Location": 'lake wanaka',
        "NotableSessionIds": '123',
        "NotableUser": True,
        "HighestRiskSession": 5,
        "EmployeeType": 'manager',
        "Department": 'my_dept',
        "Title": 'my_title'
    }]

    assert outputs == expected_outputs


def test_contents_user_info():
    user = {
        "username": 'my_user',
        "accountNames": 'my_account',
        "peerGroupFieldName": 'my_peer_group',
        "peerGroupFieldValue": 'peer51',
        "peerGroupDisplayName": 'PEER51',
        "peerGroupType": 'secret'
    }
    user_info = {
        "riskScore": 42,
        "averageRiskScore": 3,
        "lastSessionId": '123',
        "lastActivityType": 'powershell',
        'labels': 'my_label',
    }
    outputs = contents_user_info(user, user_info)

    expected_outputs = {
        'Username': 'my_user',
        'RiskScore': 42,
        'AverageRiskScore': 3,
        'LastSessionID': '123',
        'FirstSeen': None,
        'LastSeen': None,
        'LastActivityType': 'powershell',
        'Label': 'my_label',
        'AccountNames': 'my_account',
        'PeerGroupFieldName': 'my_peer_group',
        'PeerGroupFieldValue': 'peer51',
        'PeerGroupDisplayName': 'PEER51',
        'PeerGroupType': 'secret'
    }

    assert outputs == expected_outputs


@pytest.mark.parametrize('command, args, response, expected_result', [
    (get_peer_groups, {}, RESPONSE_PEER_GROUPS, EXPECTED_PEER_GROUPS),
    (get_user_labels, {}, RESPONSE_USER_LABELS, EXPECTED_USER_LABELS),
    (get_watchlist, {}, RESPONSE_WATCHLISTS, EXPECTED_WATCHLISTS),
    (get_asset_data, {'asset_name': 'dummmy'}, RESPONSE_ASSET_DATA, EXPECTED_ASSET_DATA),
    (get_session_info_by_id, {'session_id': 'dummmy'}, RESPONSE_SESSION_INFO, EXPECTED_SESSION_INFO),
    (get_rules_model_definition, {'model_name': 'dummmy'}, RESPONSE_MODEL_DATA, EXPECTED_MODEL_DATA)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    import requests
    requests.packages.urllib3.disable_warnings()

    mocker.patch.object(Client, '_login')
    client = Client('http://exabeam.com/api/auth/login', verify=False, username='user',
                    password='1234', proxy=False, headers={})

    mocker.patch.object(client, '_http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command


@pytest.mark.parametrize('records_input, fmt, is_delete, expected_result', [
    ('k1:v1,v2:,v3:v31;v32', 'key:value', False, [{'key': 'k1', 'value': ['v1']},
                                                  {'key': 'v2', 'value': []},
                                                  {'key': 'v3', 'value': ['v31', 'v32']}]),

    ('k1,k2', 'id', True, [{'id': 'k1', 'key': ''}, {'id': 'k2', 'key': ''}]),

    ('id1:k1:v1,id2:k2:,id3:k3:v31;v32', 'id:key:value', False, [{'id': 'id1', 'key': 'k1', 'value': ['v1']},
                                                                 {'id': 'id2', 'key': 'k2', 'value': []},
                                                                 {'id': 'id3', 'key': 'k3', 'value': ['v31', 'v32']}])
])  # noqa: E124
def test_parse_context_table_records_list_good_input(records_input, fmt, is_delete, expected_result):
    """
    Given:
        Valid inputs of context table records
    When:
        Running parse_context_table_records_list.
    Then:
        An equivalent records data, in the payload request format.
    """
    records_list = records_input.split(',')
    result = parse_context_table_records_list(records_list, fmt, is_delete)
    assert result == expected_result


@pytest.mark.parametrize('records_input, fmt, is_delete', [
    ('k1:v1,v2:,v3:v31;v32', 'id:key:value', False),
    ('k1:v1,k2:v2', 'id', True),
    ('id1:k1:v1,id2:k2:,id3:k3:v31;v32', 'key:value', False)
])  # noqa: E124
def test_parse_context_table_records_list_bad_input(records_input, fmt, is_delete):
    """
    Given:
        Invalid inputs of context table records
    When:
        Running parse_context_table_records_list.
    Then:
        Make sure a ValueError exception is thrown.
    """
    records_list = records_input.split(',')
    try:
        parse_context_table_records_list(records_list, fmt, is_delete)
        assert False
    except ValueError:
        assert True

import pytest
from Exabeam import Client, contents_append_notable_user_info, contents_user_info, get_peer_groups, \
    get_user_labels, get_watchlist, get_asset_data
from test_data.response_constants import RESPONSE_PEER_GROUPS, RESPONSE_USER_LABELS, RESPONSE_WATCHLISTS, \
    RESPONSE_ASSET_DATA
from test_data.result_constants import EXPECTED_PEER_GROUPS, EXPECTED_USER_LABELS, EXPECTED_WATCHLISTS, \
    EXPECTED_ASSET_DATA


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
    (get_asset_data, {'asset_name': 'dummmy'}, RESPONSE_ASSET_DATA, EXPECTED_ASSET_DATA)
])  # noqa: E124
def test_commands(command, args, response, expected_result, mocker):
    mocker.patch.object(Client, '_login')
    client = Client('http://exabeam.com/api/auth/login', verify=True, username='user',
                    password='1234', proxies={}, headers={})

    mocker.patch.object(client, 'http_request', return_value=response)
    result = command(client, args)
    assert expected_result == result[1]  # entry context is found in the 2nd place in the result of the command

from Exabeam import contents_append_notable_user_info, contents_user_info


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

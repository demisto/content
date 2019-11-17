from Exabeam import contents_append_notable_user_info


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

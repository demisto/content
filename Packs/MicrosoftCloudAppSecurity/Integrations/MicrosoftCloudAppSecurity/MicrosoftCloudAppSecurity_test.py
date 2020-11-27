import pytest
import json
from MicrosoftCloudAppSecurity import Client


def get_fetch_data():
    with open('./test_data.json', 'r') as f:
        return json.loads(f.read())


expected_filtered_alerts = {'filters': {'severity': {'eq': 0}, 'resolutionStatus': {'eq': 0}},
                            'skip': 5, 'limit': 10}
response_alerts_data = {"service": "111", "instance": "111", "severity": "Low",
                        "resolution_status": "Open", "skip": "5", "limit": "10"}


expected_filtered_activities = {'filters': {'ip.address': {'eq': '8.8.8.8'}, 'ip.category': {'eq': 1},
                                            'activity.takenAction': {'eq': 'block'}, 'source': {'eq': 0}},
                                'skip': 5, 'limit': 10}
response_activities_data = {"ip": "8.8.8.8", "ip_category": "Corporate",
                            'taken_action': 'block', 'source': 'Access_control', "skip": "5", "limit": "10"}


expected_filtered_files = {'filters': {'fileType': {'eq': 0}, 'quarantined': {'eq': True}, 'sharing': {'eq': 0},
                                       'extension': {'eq': 'png'}}, 'skip': 5, 'limit': 10}
response_files_data = {"file_type": "Other", "sharing": 'Private',
                       'extension': 'png', 'quarantined': 'True', "skip": "5", "limit": "10"}


expected_filtered_users_accounts = {'filters': {'type': {'eq': 'user'}, 'isExternal': {'eq': True}, 'status': {'eq': 0},
                                                'userGroups': {'eq': '1234'}, 'isAdmin': {'eq': 'demisto'}},
                                    'skip': 5, 'limit': 10}
response_users_accounts_data = {"type": "user", "status": 'N/A', "group_id": '1234', 'is_admin': 'demisto',
                                'is_external': 'External', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "response_data, expected",
    [
        (response_alerts_data, expected_filtered_alerts),
        (response_activities_data, expected_filtered_activities),
        (response_files_data, expected_filtered_files),
        (response_users_accounts_data, expected_filtered_users_accounts)
    ]
)
def test_args_to_filter(response_data, expected):
    from MicrosoftCloudAppSecurity import args_to_filter
    res = args_to_filter(response_data)
    assert res == expected


@pytest.mark.parametrize(
    "alert_ids, customer_filters, comment, expected",
    [
        ("5f06d71dba4,289d0602ba5ac", '', '', {'filters': {'id': {'eq': ['5f06d71dba4', '289d0602ba5ac']}}}),
        ("5f06d71dba4", '', 'Irrelevant', {"comment": "Irrelevant", 'filters': {'id': {'eq': ['5f06d71dba4']}}}),
        ("", '{"filters": {"id": {"eq": ["5f06d71dba4"]}}}', "", {'filters': {'id': {'eq': ['5f06d71dba4']}}})
    ]
)
def test_args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment, expected):
    from MicrosoftCloudAppSecurity import args_to_filter_for_dismiss_and_resolve_alerts
    res = args_to_filter_for_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    assert res == expected


client_mocker = Client(base_url='https://demistodev.eu2.portal.cloudappsecurity.com/api/v1')


def test_list_alerts_command(requests_mock):
    alert = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_alerts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/5f06d71dba4289d0602ba5ac',
                      json=alert['ALERT_BY_ID_DATA'])
    res = list_alerts_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac'})
    assert res.outputs[0] == alert['ALERT_BY_ID_DATA_CONTEXT']


def test_list_activities_command(requests_mock):
    activities = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_activities_command
    from CommonServerPython import Common
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/activities/'
                      '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
                      json=activities["ACTIVITIES_BY_ID_DATA"])
    res = list_activities_command(client_mocker, {'activity_id': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7'})
    assert res[0].outputs[0] == activities["ACTIVITIES_BY_ID_DATA_CONTEXT"]
    assert isinstance(res[0].indicator, Common.IP)
    assert res[0].indicator.ip == '8.8.8.8'
    assert res[0].indicator.geo_latitude == 32.0679
    assert res[0].indicator.geo_longitude == 34.7604


def test_list_files_command(requests_mock):
    files = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_files_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/files/5f077ebfc3b664209dae1f6b',
                      json=files["FILES_BY_ID_DATA"])
    res = list_files_command(client_mocker, {'file_id': '5f077ebfc3b664209dae1f6b'})
    assert res.outputs[0] == files["FILES_BY_ID_DATA_CONTEXT"]


def test_list_users_accounts_command(requests_mock):
    users_accounts = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_users_accounts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/entities/',
                      json=users_accounts["ENTITIES_BY_USERNAME_DATA"])
    res = list_users_accounts_command(client_mocker,
                                      {'username': '{ "id": "7e14f6a3-185d-49e3-85e8-40a33d90dc90",'
                                                   ' "saas": 11161, "inst": 0 }'})
    assert users_accounts["ENTITIES_BY_USERNAME_DATA_CONTEXT"] == res.outputs[0]


@pytest.mark.parametrize(
    "severity, resolution_status, expected",
    [
        (['All'], ['All'], {'resolutionStatus': {'eq': [0, 1, 2]}, 'severity': {'eq': [0, 1, 2]}}),
        (['Low'], ['Open', 'Dismissed'], {'resolutionStatus': {'eq': [0, 1]}, 'severity': {'eq': 0}}),
        ([], [], {'resolutionStatus': {'eq': []}, 'severity': {'eq': []}})
    ]
)
def test_params_to_filter(severity, resolution_status, expected):
    from MicrosoftCloudAppSecurity import params_to_filter
    res = params_to_filter(severity, resolution_status)
    assert res == expected


def test_alerts_to_incidents_and_fetch_start_from(requests_mock):
    """
    Given:
        `getLastRun` which holds `last_fetch` and `last_fetch_id`.
    When:
        There are two incidents to fetch, That one of them we had already fetched the previous time.
    Then:
        We only fetched the one that does not exist in his system.
    """
    from MicrosoftCloudAppSecurity import alerts_to_incidents_and_fetch_start_from
    incidents = get_fetch_data()
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/',
                      json=incidents["incidents"])
    res_incidents, fetch_start_time, new_last_fetch_id = \
        alerts_to_incidents_and_fetch_start_from(incidents["incidents"], 1602771392519, {"last_fetch": 1603365903,
                                                 "last_fetch_id": "5f919e55b0703c2f5a23d9d8"})
    assert fetch_start_time == 1603385903000
    assert new_last_fetch_id == "5f919e55b0703c2f5a23d9d7"
    assert res_incidents == [{'name': 'block1', 'occurred': '2020-10-22T16:58:23Z',
                              'rawJSON': '{"_id": "5f919e55b0703c2f5a23d9d7", "timestamp": 1603385903000, '
                              '"title": "block1"}'}]

    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/',
                      json=[])
    res_incidents, fetch_start_time, new_last_fetch_id = \
        alerts_to_incidents_and_fetch_start_from([], 1602771392519, {"last_fetch": 1603365903,
                                                 "last_fetch_id": "5f919e55b0703c2f5a23d9d8"})
    assert fetch_start_time == 1602771392519
    assert new_last_fetch_id == "5f919e55b0703c2f5a23d9d8"
    assert res_incidents == []

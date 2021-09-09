from datetime import datetime

import pytest
import json

from CommonServerPython import DemistoException
from MicrosoftCloudAppSecurity import Client


def get_fetch_data():
    with open('test_data/test_data.json', 'r') as f:
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
        ("6060c4300be9cfd6182c934d,605c63ff0be9cfd618f0dcb1", '', '',
         {'filters': {'id': {'eq': ['6060c4300be9cfd6182c934d', '605c63ff0be9cfd618f0dcb1']}}}),
        ("6060c4300be9cfd6182c934d", '', 'Irrelevant',
         {"comment": "Irrelevant", 'filters': {'id': {'eq': ['6060c4300be9cfd6182c934d']}}}),
        ("", '{"filters": {"id": {"eq": ["6060c4300be9cfd6182c934d"]}}}', "",
         {'filters': {'id': {'eq': ['6060c4300be9cfd6182c934d']}}})
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
    assert float(res[0].indicator.geo_latitude) == 32.0679
    assert float(res[0].indicator.geo_longitude) == 34.7604


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


@pytest.mark.parametrize(
    "incidents,last_run, expected_last_run, expected_incidents",
    [
        ({}, {'last_fetch': '1615228302580', 'fetched_ids_dict': {'1615228302580': ['id2']}},
         {'last_fetch': '1615228302580', 'fetched_ids_dict': {'1615228302580': ['id2']}}, []),
        (get_fetch_data()["alerts_response_data"],
         {'last_fetch': '1615228302580', 'fetched_ids_dict': {'1615228302580': ['id2']}},
         {'last_fetch': '1615228302080', 'fetched_ids_dict': {'1615228302580': ['id2'], '1615228302080': ('id1',)}},
         [{'name': 'Impossible travel activity',
           'occurred': datetime.fromtimestamp(1615228302).isoformat() + 'Z',
           'rawJSON':
               '{"_id": "id1",'
               ' "contextId": "contextId",'
               ' "timestamp": 1615228302080,'
               ' "title": "Impossible travel activity",'
               ' "service": [{"id": 1, "type": "service", "label": "Microsoft Exchange Online"}]}'
           }]),
        (get_fetch_data()["alerts_response_data"], {},
         {'last_fetch': '1615228302080', 'fetched_ids_dict': {'1615228302080': ('id1',)}},
         [{'name': 'Impossible travel activity',
           'occurred': datetime.fromtimestamp(1615228302).isoformat() + 'Z',
           'rawJSON': '{"_id": "id1",'
                      ' "contextId": "contextId",'
                      ' "timestamp": 1615228302080,'
                      ' "title": "Impossible travel activity",'
                      ' "service": [{"id": 1, "type": "service", "label": "Microsoft Exchange Online"}]}'
           }]
         ),
        ({}, {}, {}, [])
    ]
)
def test_fetch_incidents(mocker, incidents, last_run, expected_last_run, expected_incidents):
    """
    Given:
        `getLastRun` which holds `last_fetch` and `fetched_ids`.
    When:
        There are new incidents with time stamp older than the last fetch.
    Then:
        Fetch only the new incidents.
    """
    from MicrosoftCloudAppSecurity import fetch_incidents
    mocker.patch('MicrosoftCloudAppSecurity.Client.list_incidents', return_value=incidents)
    next_run, incidents = fetch_incidents(client=client_mocker, max_results=None,
                                          last_run=last_run,
                                          first_fetch=None, filters={}, fetch_delta_time=30)
    assert next_run == expected_last_run
    assert list(incidents) == expected_incidents


def test_convert_alert_to_incident():
    """
    Given:
        Raw alert.
    When:
        Running convert_alert_to_incident.
    Then:
        Check that incident is properly converted.
    """
    from MicrosoftCloudAppSecurity import convert_alert_to_incident
    alert = get_fetch_data()["incidents"][0]
    incident = convert_alert_to_incident(alert)
    assert incident['name'] == alert['title']
    assert incident['occurred'] == datetime.fromtimestamp(1603378041).isoformat() + 'Z'
    assert incident['rawJSON'] == '{"_id": "id1", "timestamp": 1603378041000, "title": "block0"}'


@pytest.mark.parametrize(
    "last_fetch,first_fetch,fetch_buffer_time,expected",
    [
        (None, None, 0, 1630255838000),
        (1630255838000, None, 30, 1630254038000)
    ]
)
def test_calculate_fetch_start_time(mocker, last_fetch, first_fetch, fetch_buffer_time, expected):
    """
    Given:
        last_fetch first_fetch fetch_buffer_time
    When:
        Running calculate_fetch_start_time.
    Then:
        Check that the generated timestamp is correct
    """
    from MicrosoftCloudAppSecurity import calculate_fetch_start_time
    mocker.patch('MicrosoftCloudAppSecurity.parse_date_to_timestamp', return_value=1630255838000)
    res = calculate_fetch_start_time(last_fetch, first_fetch, fetch_buffer_time)
    assert res == expected


class TestCloseBenign:
    def setup(self):
        self.success_response = get_fetch_data()['CLOSE_BENIGN_SUCCESS']
        self.failure_response = get_fetch_data()['CLOSE_BENIGN_FAILURE']

    def test_sanity_ids(self, requests_mock):
        """
        Given:
            - List of alerts.
        When:
            - Closing requested alerts as benign.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_benign_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_benign/',
                           json=self.success_response)

        res = close_benign_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as benign.' in res.readable_output

    def test_sanity_filter(self, requests_mock):
        """
        Given:
            - a custom filter.
        When:
            - Closing requested alerts as benign.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_benign_command
        custom_filter = {
            'filters': {
                'id': {
                    'eq': [
                        '6060c4300be9cfd6182c934d',
                        '604f14400be9cfd6181b13fb',
                    ],
                },
            },
        }
        args = {"custom_filter": json.dumps(custom_filter)}
        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_benign/',
                           json=self.success_response)

        res = close_benign_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as benign.' in res.readable_output

    def test_sanity_filter_dict(self, requests_mock):
        """
        Given:
            - a custom filter as dict (use-case: taken from context).
        When:
            - Closing requested alerts as benign.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_benign_command
        custom_filter = {
            'filters': {
                'id': {
                    'eq': [
                        '6060c4300be9cfd6182c934d',
                        '604f14400be9cfd6181b13fb',
                    ],
                },
            },
        }
        args = {"custom_filter": custom_filter}
        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_benign/',
                           json=self.success_response)

        res = close_benign_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as benign.' in res.readable_output

    def test_failure_not_found(self, requests_mock):
        """
        Given:
            - list of alerts including invalid alert id.
        When:
            - Closing requested alerts as benign.
        Then:
            - Command failure.
        """
        from MicrosoftCloudAppSecurity import close_benign_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb,invalidAlert1,invalidAlert2'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_benign/',
                           json=self.failure_response)

        with pytest.raises(DemistoException, match='Failed to close the following alerts:.*'):
            close_benign_command(client_mocker, args)

    def test_failure_invalid_input(self):
        """
        Given:
            - no alert ids nor filter.
        When:
            - Closing requested alerts as benign.
        Then:
            - Command failure.
        """
        from MicrosoftCloudAppSecurity import close_benign_command

        with pytest.raises(DemistoException, match='Expecting at least one of the following arguments:'
                                                   ' alert_id, custom_filter.'):
            close_benign_command(client_mocker, {})


class TestCloseTruePositive:
    def setup(self):
        self.success_response = get_fetch_data()['CLOSE_TRUE_POSITIVE_SUCCESS']
        self.failure_response = get_fetch_data()['CLOSE_TRUE_POSITIVE_FAILURE']

    def test_sanity_ids(self, requests_mock):
        """
        Given:
            - List of alerts.
        When:
            - Close requested alerts as true-positive.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_true_positive_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_true_positive/',
                           json=self.success_response)

        res = close_true_positive_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as true-positive.' in res.readable_output

    def test_sanity_filter(self, requests_mock):
        """
        Given:
            - a custom filter.
        When:
            - Close requested alerts as true-positive.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_true_positive_command
        custom_filter = {
            'filters': {
                'id': {
                    'eq': [
                        '6060c4300be9cfd6182c934d',
                        '604f14400be9cfd6181b13fb',
                    ],
                },
            },
        }
        args = {"custom_filter": json.dumps(custom_filter)}
        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_true_positive/',
                           json=self.success_response)

        res = close_true_positive_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as true-positive.' in res.readable_output

    def test_failure_not_found(self, requests_mock):
        """
        Given:
            - list of alerts including invalid alert id.
        When:
            - Close requested alerts as true-positive.
        Then:
            - Command failure.
        """
        from MicrosoftCloudAppSecurity import close_true_positive_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb,invalidAlert1,invalidAlert2'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_true_positive/',
                           json=self.failure_response)

        with pytest.raises(DemistoException, match='Failed to close the following alerts:.*'):
            close_true_positive_command(client_mocker, args)


class TestCloseFalsePositive:
    def setup(self):
        self.success_response = get_fetch_data()['CLOSE_FALSE_POSITIVE_SUCCESS']
        self.failure_response = get_fetch_data()['CLOSE_FALSE_POSITIVE_FAILURE']

    def test_sanity_ids(self, requests_mock):
        """
        Given:
            - List of alerts.
        When:
            - Close requested alerts as false-positive.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_false_positive_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_false_positive/',
                           json=self.success_response)

        res = close_false_positive_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as false-positive.' in res.readable_output

    def test_sanity_filter(self, requests_mock):
        """
        Given:
            - a custom filter.
        When:
            - Close requested alerts as false-positive.
        Then:
            - Command success.
        """
        from MicrosoftCloudAppSecurity import close_false_positive_command
        custom_filter = {
            'filters': {
                'id': {
                    'eq': [
                        '6060c4300be9cfd6182c934d',
                        '604f14400be9cfd6181b13fb',
                    ],
                },
            },
        }
        args = {"custom_filter": json.dumps(custom_filter)}
        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_false_positive/',
                           json=self.success_response)

        res = close_false_positive_command(client_mocker, args)
        assert res.raw_response == self.success_response
        assert '2 alerts were closed as false-positive.' in res.readable_output

    def test_failure_not_found(self, requests_mock):
        """
        Given:
            - list of alerts including invalid alert id.
        When:
            - Close requested alerts as false-positive.
        Then:
            - Command failure.
        """
        from MicrosoftCloudAppSecurity import close_false_positive_command
        alert_ids = '6060c4300be9cfd6182c934d,604f14400be9cfd6181b13fb,invalidAlert1,invalidAlert2'
        args = {'alert_ids': alert_ids}

        requests_mock.post('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/close_false_positive/',
                           json=self.failure_response)

        with pytest.raises(DemistoException, match='Failed to close the following alerts:.*'):
            close_false_positive_command(client_mocker, args)

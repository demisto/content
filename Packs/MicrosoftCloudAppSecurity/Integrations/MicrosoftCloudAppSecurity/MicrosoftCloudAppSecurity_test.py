from datetime import datetime
import json
from typing import Any

import pytest

import demistomock as demisto

from freezegun import freeze_time
from CommonServerPython import DemistoException, timedelta
from MicrosoftCloudAppSecurity import Client, fetch_incidents
from MicrosoftApiModule import AZURE_WORLDWIDE_CLOUD


def get_fetch_data():
    with open('test_data/test_data.json') as f:
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


client_mocker = Client(base_url='https://demistodev.eu2.portal.cloudappsecurity.com/api/v1', app_id='1234', verify=True,
                       proxy=True, endpoint_type='Worldwide', auth_mode='legacy', azure_cloud=AZURE_WORLDWIDE_CLOUD)


def test_list_alerts_command(requests_mock):
    alert = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_alerts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/5f06d71dba4289d0602ba5ac',
                      json=alert['ALERT_BY_ID_DATA'])
    res = list_alerts_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac'})
    assert res.outputs[0] == alert['ALERT_BY_ID_DATA_CONTEXT']


def test_list_alerts_command_no_alerts(requests_mock):
    from MicrosoftCloudAppSecurity import list_alerts_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/5f06d71dba4289d0602ba5ac',
                      json={"data": []})
    res = list_alerts_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac', 'custom_filter': []})
    assert res.readable_output == "No alerts found for the given filter: []."


def test_list_activities_command(requests_mock):
    activities = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_activities_command
    from CommonServerPython import Common
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/activities/'
                      '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7',
                      json=activities["ACTIVITIES_BY_ID_DATA"])
    res = list_activities_command(client_mocker, {'activity_id': '97134000_15600_97ee2049-893e-4c9d-a312-08d82b46faf7'})
    assert not isinstance(res[0].outputs, list)
    assert res[0].outputs == activities["ACTIVITIES_BY_ID_DATA_CONTEXT"]
    assert isinstance(res[0].indicator, Common.IP)
    assert res[0].indicator.ip == '8.8.8.8'
    assert float(res[0].indicator.geo_latitude) == 32.0679
    assert float(res[0].indicator.geo_longitude) == 34.7604


def test_list_files_command(requests_mock):
    files = get_fetch_data()
    from MicrosoftCloudAppSecurity import list_files_command
    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/files/5f077e6fc3b664209dae1f6b',
                      json=files["FILES_BY_ID_DATA"])
    res = list_files_command(client_mocker, {'file_id': '5f077e6fc3b664209dae1f6b'})
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


def start_freeze_time(timestamp):
    _start_freeze_time = freeze_time(timestamp)
    _start_freeze_time.start()
    return datetime.now()


def create_occur_timestamp(timestamp, timedelta_object=timedelta(minutes=0)):
    return int((start_freeze_time(timestamp) - timedelta_object).timestamp()) * 1000


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


class TestFetchIncidents:
    LAST_RUN: dict[str, Any] = {}
    FREEZE_TIMESTAMP = '2022-05-15T11:00:00.000'

    @pytest.mark.parametrize(
        'params, start_incidents, phase2_incident, phase3_incident',
        [
            ({'limit': 50, 'first_fetch': '50 minutes', 'look_back': 15},
             {'data': [
                 {
                     'title': 'test2',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=10)),
                     '_id': '2',
                     'entities': []
                 },
                 {
                     'title': 'test4',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=5)),
                     '_id': '4',
                     'entities': []
                 },
                 {
                     'title': 'test5',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=2)),
                     '_id': '5',
                     'entities': []
                 }
             ]},
             {
                 'title': 'test3',
                 'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=8)),
                 '_id': '3',
                 'entities': []
            },
                {
                 'title': 'test1',
                 'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=11)),
                 '_id': '1',
                 'entities': []
            }),
            ({'limit': 50, 'first_fetch': '50 minutes', 'look_back': 1000},
             {'data': [
                 {
                     'title': 'test2',
                     'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=3, minutes=20)),
                     '_id': '2',
                     'entities': []
                 },
                 {
                     'title': 'test4',
                     'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=2, minutes=26)),
                     '_id': '4',
                     'entities': []
                 },
                 {
                     'title': 'test5',
                     'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=1, minutes=20)),
                     '_id': '5',
                     'entities': []
                 }
             ]},
             {
                 'title': 'test3',
                 'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=2, minutes=45)),
                 '_id': '3',
                 'entities': []
            },
                {
                 'title': 'test1',
                 'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=3, minutes=50)),
                 '_id': '1',
                 'entities': []
            })
        ]
    )
    def test_fetch_incidents_with_look_back_greater_than_zero(
            self, mocker, params, start_incidents, phase2_incident, phase3_incident
    ):
        """
        Given
        - fetch incidents parameters including look back according to their opened time.
        - first scenario - fetching with minutes when look_back=60 minutes
        - second scenario - fetching with hours when look_back=1000 minutes

        When
        - trying to fetch incidents for 3 rounds.

        Then
        - first fetch - should fetch incidents 2, 4, 5 (because only them match the query)
        - second fetch - should fetch incident 3 (because now incident 2, 4, 5, 3 matches the query too)
        - third fetch - should fetch incident 1 (because now incident 2, 4, 5, 3, 1 matches the query too)
        - fourth fetch - should fetch nothing as there are no new incidents who match the query
        - make sure that incidents who were already fetched would not be fetched again.
        """

        # reset last run
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)

        mocker.patch.object(client_mocker, 'list_incidents', return_value=start_incidents)
        mocker.patch('MicrosoftCloudAppSecurity.format_fetch_start_time_to_timestamp',
                     side_effect=create_occur_timestamp)

        filters: dict[str, Any] = {'severity': {'eq': []}, 'resolutionStatus': {'eq': []}}
        max_results = params.get('limit')
        first_fetch = params.get('first_fetch')
        look_back = params.get('look_back')

        # Run first fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 3
        for expected_incident_id, alert in zip(['2', '4', '5'], alerts):
            assert alert.get('name') == f'test{expected_incident_id}'

        # second fetch preparation
        for alert in start_incidents.get('data'):
            alert['entities'] = []
        start_incidents.get('data').append(phase2_incident)

        # Run second fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 1
        assert alerts[0].get('name') == 'test3'

        # third fetch preparation
        for alert in start_incidents.get('data'):
            alert['entities'] = []
        start_incidents.get('data').append(phase3_incident)

        # Run third fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 1
        assert alerts[0].get('name') == 'test1'

        # Fourth fetch preparation
        for alert in start_incidents.get('data'):
            alert['entities'] = []

        # Run fourth fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 0

    @pytest.mark.parametrize(
        'params, incidents, phase2_incident, phase3_incident',
        [
            ({'limit': 50, 'first_fetch': '50 minutes', 'look_back': 0},
             {'data': [
                 {
                     'title': 'test1',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=10)),
                     '_id': '1',
                     'entities': []
                 },
                 {
                     'title': 'test2',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=8)),
                     '_id': '2',
                     'entities': []
                 },
                 {
                     'title': 'test3',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=7)),
                     '_id': '3',
                     'entities': []
                 }
             ]},
             {'data': [
                 {
                     'title': 'test4',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=5)),
                     '_id': '4',
                     'entities': []
                 }
             ]},
             {'data': [
                 {
                     'title': 'test5',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=4)),
                     '_id': '5',
                     'entities': []
                 }
             ]},
             ),
            ({'limit': 50, 'first_fetch': '3 days', 'look_back': 0},
             {
                 'data': [
                     {
                         'title': 'test1',
                         'timestamp':
                             create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=8, minutes=51)),
                         '_id': '1',
                         'entities': []
                     },
                     {
                         'title': 'test2',
                         'timestamp':
                             create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=7, minutes=45)),
                         '_id': '2',
                         'entities': []
                     },
                     {
                         'title': 'test3',
                         'timestamp':
                             create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=7, minutes=44)),
                         '_id': '3',
                         'entities': []
                     }
                 ]
            },
                {'data': [
                 {
                     'title': 'test4',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=7, minutes=44)),
                     '_id': '4',
                     'entities': []
                 }
                 ]
                 },
                {'data': [
                 {
                     'title': 'test5',
                     'timestamp':
                         create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(hours=1, minutes=34)),
                     '_id': '5',
                     'entities': []
                 }
                 ]
                 }
            )
        ]
    )
    def test_fetch_incidents_with_look_back_equals_zero(
        self, mocker, params, incidents, phase2_incident, phase3_incident
    ):
        """
        Given
        - fetch incidents parameters with any look back according to their opened time (normal fetch incidents).
        - first scenario - fetching with minutes when look_back=0
        - second scenario - fetching with hours when look_back=0

        When
        - trying to fetch incidents for 3 rounds.

        Then
        - first fetch - should fetch incidents 1, 2, 3 (because only them match the query)
        - second fetch - should fetch incident 4
        - third fetch - should fetch incident 5
        - fourth fetch - should fetch nothing as there are no new incidents who match the query
        """

        # reset last fetch and tickets
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)
        mocker.patch('MicrosoftCloudAppSecurity.format_fetch_start_time_to_timestamp',
                     side_effect=create_occur_timestamp)

        filters: dict[str, Any] = {'severity': {'eq': []}, 'resolutionStatus': {'eq': []}}
        max_results = params.get('limit')
        first_fetch = params.get('first_fetch')
        look_back = params.get('look_back')

        # first fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 3
        for expected_incident_id, ticket in zip(['1', '2', '3'], alerts):
            assert ticket.get('name') == f'test{expected_incident_id}'

        # second fetch preparation
        incidents = phase2_incident
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)

        # second fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 1
        assert alerts[0].get('name') == 'test4'

        # third fetch preparation
        incidents = phase3_incident
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)

        # third fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 1
        assert alerts[0].get('name') == 'test5'

        # forth fetch preparation
        incidents: dict[str, Any] = {'data': []}
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)

        # forth fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 0

    @pytest.mark.parametrize(
        "incidents, expected_time, last_run_start",
        [
            (
                {
                    'data': [
                        {
                            'title': 'test1',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=10)),
                            '_id': '1',
                            'entities': []
                        },
                        {
                            'title': 'test2',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=10)),
                            '_id': '2',
                            'entities': []
                        },
                    ]
                },
                '2022-05-15T10:50:00.001000',
                {}
            ),
            (
                {
                    'data': [
                        {
                            'title': 'test1',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=8)),
                            '_id': '1',
                            'entities': []
                        },
                        {
                            'title': 'test2',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=8)),
                            '_id': '2',
                            'entities': []
                        },
                    ]
                },
                '2022-05-15T10:52:00.001000',
                {'time': '2022-05-15T10:50:00.001000', "limit": 10}
            ),
            (
                {
                    'data': [
                        {
                            'title': 'test1',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=5)),
                            '_id': '1',
                            'entities': []
                        },
                        {
                            'title': 'test2',
                            'timestamp': create_occur_timestamp(FREEZE_TIMESTAMP, timedelta(minutes=5)),
                            '_id': '2',
                            'entities': []
                        },
                    ]
                },
                '2022-05-15T10:55:00.001000',
                {'time': '2022-05-15T10:50:00', "limit": 10}
            )
        ]
    )
    def test_fetch_incidents_with_different_last_runs(self, mocker, incidents, expected_time, last_run_start):
        """
        Given
        - Case A: fetching incidents without any last run
        - Case B: fetching incidents with last run containing date in miliseconds
        - Case C: fetching incidents with last run not containing date in miliseconds

        When
        - trying to fetch incidents only one round

        Then
        - make sure that the new time in the last run contains the date with miliseconds
        - make sure that the new time in the last run is increased with one milisecond
        - make sure incidents were returned and were parsed successfully
        """
        self.LAST_RUN = last_run_start

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch(
            'MicrosoftCloudAppSecurity.format_fetch_start_time_to_timestamp',
            side_effect=create_occur_timestamp
        )

        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)

        self.LAST_RUN, alerts = fetch_incidents(
            client=client_mocker, max_results='10', last_run=self.LAST_RUN,
            first_fetch='1 year ago', filters={'severity': {'eq': []}, 'resolutionStatus': {'eq': []}}, look_back=0
        )

        assert self.LAST_RUN.get('time') == expected_time
        assert len(alerts) == 2


@pytest.mark.parametrize(
    "fetch_time",
    [
        "2022-05-15T10:50:00",
        "2022-05-15T10:50:00.000",
        "2022-05-15T10:50:15.123",
        "2022-05-15T10:50:15.100",
        "2022-05-15T10:50:15.120"
    ]
)
def test_format_fetch_start_time_to_timestamp(mocker, fetch_time):
    """
    Given
    - Case A: fetch time that does not have miliseconds
    - Case B: fetch time that have miliseconds with zeros only
    - Case C + D + E: fetch time that have miliseconds that are not zeros only

    When
    - running format_fetch_start_time_to_timestamp

    Then
    - make sure we create a timestamp that is only based on 13 digits
    """
    from MicrosoftCloudAppSecurity import format_fetch_start_time_to_timestamp
    start_freeze_time(fetch_time)
    mocker.patch('MicrosoftCloudAppSecurity.parse', return_value=datetime.now())
    timestamp = format_fetch_start_time_to_timestamp(fetch_time)
    assert len(str(timestamp)) == 13


@pytest.mark.parametrize(
    "timestamp, expected_datetime_string",
    [
        (1652611800000, "2022-05-15T10:50:00.000"),
        (1652611812000, "2022-05-15T10:50:12.000"),
        (1652611812100, "2022-05-15T10:50:12.100"),
        (1652611812120, "2022-05-15T10:50:12.120"),
        (1652611812123, "2022-05-15T10:50:12.123")
    ]
)
def test_timestamp_to_datetime_string(timestamp, expected_datetime_string):
    """
    Given
    - 13 characters timestamps

    When
    - running timestamp_to_datetime_string

    Then
    - make sure a valid datetime string is created
    """
    from MicrosoftCloudAppSecurity import timestamp_to_datetime_string
    assert timestamp_to_datetime_string(timestamp) == expected_datetime_string


class TestModuleTest:
    """
    Code Analysis

    Objective:
    The test_module function is used to test the connection to the Microsoft Cloud App Security API and verify that the
    integration is properly configured. It checks the authentication mode, lists alerts, and optionally lists incidents and
    validates a custom filter.

    Inputs:
    - client: an instance of the Client class that is used to communicate with the Microsoft Cloud App Security API.
    - is_fetch: a boolean value that indicates whether to test the fetch-incidents command.
    - custom_filter: a string that contains a custom filter in JSON format.

    Flow:
    - Check if the authentication mode is device code flow and raise an exception if it is.
    - List alerts by calling the list_alerts method of the client object.
    - If is_fetch is true, list incidents by calling the list_incidents method of the client object.
    - If custom_filter is not None, validate it by parsing it as JSON.

    Outputs:
    - If the function completes without raising an exception, it returns the string 'ok'.
    - If an exception is raised, it returns an error message as a string.

    Additional aspects:
    - The function handles exceptions related to connection errors and authorization errors.
    - The function validates the custom filter by parsing it as JSON, but it does not check the validity of the filter itself.
    """

    #  Tests that the client can list alerts.
    def test_test_module_alerts(self, mocker):
        """
        Given:
        - A client object.

        When:
        - Calling the test_module function with is_fetch=False and custom_filter=None.

        Then:
        - Ensure the client can list alerts.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'Worldwide', 'https://test.com', 'legacy', AZURE_WORLDWIDE_CLOUD)
        mocker.patch.object(client, 'list_alerts', return_value=None)
        mocker.patch.object(client, 'list_alerts', return_value={})

        result = test_module(client, False, None)

        assert result == 'ok'
        client.list_alerts.assert_called_once_with(url_suffix='/alerts/', request_data={})

    #  Tests that the client can list incidents.
    def test_test_module_incidents(self, mocker):
        """
        Given:
        - A client object.

        When:
        - Calling the test_module function with is_fetch=True and custom_filter=None.

        Then:
        - Ensure the client can list incidents.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'com', 'https://test.com', 'legacy', AZURE_WORLDWIDE_CLOUD)
        mocker.patch.object(client, 'list_alerts', return_value=None)
        mocker.patch.object(client, 'list_incidents', return_value={})

        result = test_module(client, True, None)

        assert result == 'ok'
        client.list_incidents.assert_called_once_with(filters={}, limit=1)

    #  Tests that an exception is raised if the client is using device code flow.
    def test_test_module_device_code_flow(self):
        """
        Given:
        - A client object with auth_mode=device code flow.

        When:
        - Calling the test_module function.

        Then:
        - Ensure a DemistoException is raised.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'com', 'https://test.com', 'device code flow', AZURE_WORLDWIDE_CLOUD)

        assert test_module(
            client, False, None) == 'To test the device code flow Please run !microsoft-cas-auth-start and ' \
                                    '!microsoft-cas-auth-complete and check the connection using !microsoft-cas-auth-test'

    #  Tests that a DemistoException is raised if the custom filter is incorrectly formatted.
    def test_test_module_custom_filter(self, mocker):
        """
        Given:
        - A client object.

        When:
        - Calling the test_module function with is_fetch=True and an incorrectly formatted custom_filter.

        Then:
        - Ensure a DemistoException is raised.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'com', 'https://test.com', 'legacy', AZURE_WORLDWIDE_CLOUD)
        mocker.patch.object(client, 'list_alerts', return_value=None)
        mocker.patch.object(client, 'list_incidents', return_value={})

        result = test_module(client, True, '{"invalid: "json"}')
        assert result == 'Custom Filter Error: Your custom filter format is incorrect, please try again.'

    #  Tests that a connection error message is returned if there is no connection.
    def test_test_module_connection_error(self, mocker):
        """
        Given:
        - A client object that raises a connection error.

        When:
        - Calling the test_module function.

        Then:
        - Ensure a connection error message is returned.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'com', 'https://invalid-url.com', 'legacy', AZURE_WORLDWIDE_CLOUD)
        mocker.patch.object(client, 'list_alerts', side_effect=DemistoException('No connection'))

        result = test_module(client, False, None)

        assert result == 'Connection Error: The URL you entered is probably incorrect, please try again.'

    #  Tests that an authorization error message is returned if the API key is incorrect.
    def test_test_module_authorization_error(self, mocker):
        """
        Given:
        - A client object that raises an authorization error.

        When:
        - Calling the test_module function.

        Then:
        - Ensure an authorization error message is returned.
        """
        from MicrosoftCloudAppSecurity import test_module

        client = Client('app_id', True, True, 'com', 'https://test.com', 'legacy', AZURE_WORLDWIDE_CLOUD)
        mocker.patch.object(client, 'list_alerts', side_effect=DemistoException('Invalid token'))

        result = test_module(client, False, None)

        assert result == 'Authorization Error: make sure API Key is correctly set.'

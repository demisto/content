from datetime import datetime
import json

import pytest
import demistomock as demisto

from freezegun import freeze_time
from CommonServerPython import DemistoException, timedelta
from MicrosoftCloudAppSecurity import Client, fetch_incidents


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


client_mocker = Client(base_url='https://demistodev.eu2.portal.cloudappsecurity.com/api/v1', app_id='1234', verify=True,
                       proxy=True, auth_mode='legacy')


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
    assert not isinstance(res[0].outputs, list)
    assert res[0].outputs == activities["ACTIVITIES_BY_ID_DATA_CONTEXT"]
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
    res_incidents, new_last_fetch_id, alert = \
        alerts_to_incidents_and_fetch_start_from(incidents["incidents"], '1602771392519',
                                                 {"last_fetch": 1603365903,
                                                  "last_fetch_id": "5f919e55b0703c2f5a23d9d8"})
    assert new_last_fetch_id == "5f919e55b0703c2f5a23d9d7"

    requests_mock.get('https://demistodev.eu2.portal.cloudappsecurity.com/api/v1/alerts/',
                      json=[])
    res_incidents, new_last_fetch_id, alerts = \
        alerts_to_incidents_and_fetch_start_from([], '1602771392519', {"last_fetch": 1603365903,
                                                                       "last_fetch_id": "5f919e55b0703c2f5a23d9d8"})
    assert new_last_fetch_id == "5f919e55b0703c2f5a23d9d8"
    assert res_incidents == []


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


class TestFetchIncidentsWithLookBack:
    LAST_RUN = {}
    API_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
    FREEZE_TIMESTAMP = '2022-05-15T11:00:00'

    def set_last_run(self, new_last_run):
        self.LAST_RUN = new_last_run

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
        - fourth fetch - should fetch nothing as there are not new incidents who match the query
        - make sure that incidents who were already fetched would not be fetched again.
        """

        # reset last run
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)

        mocker.patch.object(client_mocker, 'list_incidents', return_value=start_incidents)
        mocker.patch('MicrosoftCloudAppSecurity.format_fetch_start_time_to_timestamp',
                     side_effect=create_occur_timestamp)

        filters = {'severity': {'eq': []}, 'resolutionStatus': {'eq': []}}
        max_results = params.get('limit')
        first_fetch = params.get('first_fetch')
        look_back = params.get('look_back')

        # Run first fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 3
        assert self.LAST_RUN.get('last_fetch_id') == '5'
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
        - fourth fetch - should fetch nothing as there are not new incidents who match the query
        """

        # reset last fetch and tickets
        self.LAST_RUN = {}

        mocker.patch.object(demisto, 'getLastRun', return_value=self.LAST_RUN)
        mocker.patch.object(demisto, 'setLastRun', side_effect=self.set_last_run)
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)
        mocker.patch('MicrosoftCloudAppSecurity.format_fetch_start_time_to_timestamp',
                     side_effect=create_occur_timestamp)

        filters = {'severity': {'eq': []}, 'resolutionStatus': {'eq': []}}
        max_results = params.get('limit')
        first_fetch = params.get('first_fetch')
        look_back = params.get('look_back')

        # first fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 3
        assert self.LAST_RUN.get('last_fetch_id') == '3'
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
        assert self.LAST_RUN.get('last_fetch_id') == '5'
        assert alerts[0].get('name') == 'test5'

        # forth fetch preparation
        incidents = {'data': []}
        mocker.patch.object(client_mocker, 'list_incidents', return_value=incidents)

        # forth fetch
        self.LAST_RUN, alerts = fetch_incidents(client=client_mocker, max_results=max_results, last_run=self.LAST_RUN,
                                                first_fetch=first_fetch, filters=filters, look_back=look_back)
        assert len(alerts) == 0

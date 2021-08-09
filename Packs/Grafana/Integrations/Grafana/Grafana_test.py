import dateparser
import pytest
from pytz import utc

from Grafana import Client, change_key, lower_keys, decapitalize, url_encode, calculate_fetch_start_time, \
    parse_alerts, parse_alert
from freezegun import freeze_time
from CommonServerPython import urljoin


def create_client(url: str = 'url', verify_certificate: bool = False, proxy: bool = False):
    return Client(urljoin(url, ''), verify_certificate, proxy)


CHANGE_KEY_VALUES = [
    (
        {
            "alertId": 2,
            "message": "Alert is already paused",
            "state": "paused"
        },
        "alertId",
        "id",
        {
            "id": 2,
            "message": "Alert is already paused",
            "state": "paused"
        }),
    (
        {
            "message": "Team created",
            "teamId": 6
        },
        "teamId",
        "id",
        {
            "message": "Team created",
            "id": 6
        }),
    (
        {
            "message": "Organization created",
            "orgId": 3
        },
        "orgId",
        "id",
        {
            "message": "Organization created",
            "id": 3
        })]


@pytest.mark.parametrize('dict_input, prev_key, new_key, expected_result', CHANGE_KEY_VALUES)
def test_change_key(dict_input, prev_key, new_key, expected_result):
    """

    Given:
        - Dictionary we want to change it's keys

    When:
        - Getting response from Grafana API

    Then:
        - Returns the dictionary with the wanted key changed

    """
    assert change_key(dict_input, prev_key, new_key) == expected_result


def test_lower_keys():
    """

    Given:
        - Dictionary we want to change it's keys to decapitalized

    When:
        - Getting response about an alert

    Then:
        - Returns the dictionary with it's keys decapitalized

    """
    dict_input = {
        "Id": 1,
        "Version": 0,
        "OrgId": 1,
        "DashboardId": 1,
        "PanelId": 4,
        "Name": "Arseny's Alert",
        "Message": "man down!",
        "Severity": "",
        "State": "no_data",
        "Handler": 1,
        "Silenced": False,
        "ExecutionError": " ",
        "Frequency": 600,
        "For": 60000000000,
        "EvalData": {
            "noData": True
        },
        "NewStateDate": "2021-06-09T15:20:01Z",
        "StateChanges": 1,
        "Created": "2021-06-09T15:13:45Z",
        "Updated": "2021-06-09T15:14:51Z",
        "Settings": {
            "alertRuleTags": {
                "moshe": "2"
            },
            "conditions": [
                {
                    "evaluator": {
                        "params": [
                            10
                        ],
                        "type": "gt"
                    },
                    "operator": {
                        "type": "and"
                    },
                    "query": {
                        "datasourceId": 1,
                        "model": {
                            "refId": "A",
                            "scenarioId": "streaming_client",
                            "stream": {
                                "noise": 2.2,
                                "speed": 100,
                                "spread": 3.5,
                                "type": "signal"
                            },
                            "stringInput": ""
                        },
                        "params": [
                            "A",
                            "5m",
                            "now"
                        ]
                    },
                    "reducer": {
                        "params": [],
                        "type": "avg"
                    },
                    "type": "query"
                }
            ],
            "executionErrorState": "alerting",
            "for": "1m",
            "frequency": "10m",
            "handler": 1,
            "message": "man down!",
            "name": "Arseny's Alert",
            "noDataState": "no_data",
            "notifications": []
        }
    }
    expected_result = {
        "id": 1,
        "version": 0,
        "orgId": 1,
        "dashboardId": 1,
        "panelId": 4,
        "name": "Arseny's Alert",
        "message": "man down!",
        "severity": "",
        "state": "no_data",
        "handler": 1,
        "silenced": False,
        "executionError": " ",
        "frequency": 600,
        "for": 60000000000,
        "evalData": {
            "noData": True
        },
        "newStateDate": "2021-06-09T15:20:01Z",
        "stateChanges": 1,
        "created": "2021-06-09T15:13:45Z",
        "updated": "2021-06-09T15:14:51Z",
        "settings": {
            "alertRuleTags": {
                "moshe": "2"
            },
            "conditions": [
                {
                    "evaluator": {
                        "params": [
                            10
                        ],
                        "type": "gt"
                    },
                    "operator": {
                        "type": "and"
                    },
                    "query": {
                        "datasourceId": 1,
                        "model": {
                            "refId": "A",
                            "scenarioId": "streaming_client",
                            "stream": {
                                "noise": 2.2,
                                "speed": 100,
                                "spread": 3.5,
                                "type": "signal"
                            },
                            "stringInput": ""
                        },
                        "params": [
                            "A",
                            "5m",
                            "now"
                        ]
                    },
                    "reducer": {
                        "params": [],
                        "type": "avg"
                    },
                    "type": "query"
                }
            ],
            "executionErrorState": "alerting",
            "for": "1m",
            "frequency": "10m",
            "handler": 1,
            "message": "man down!",
            "name": "Arseny's Alert",
            "noDataState": "no_data",
            "notifications": []
        }
    }
    assert lower_keys(dict_input) == expected_result


DECAPITALIZE_VALUES = {
    ('ID', 'iD'),
    ('Id', 'id'),
    ('', ''),
    ('NewStateDate', 'newStateDate')
}


@pytest.mark.parametrize('str_input, expected_output', DECAPITALIZE_VALUES)
def test_decapitalize(str_input, expected_output):
    """

    Given:
        - A string we want to decapitalized

    When:
        - Lowering keys in dictionary

    Then:
        - Returns the string decapitalized

    """
    assert decapitalize(str_input) == expected_output


URL_ENCODE_VALUES = [
    ('Jane Doe', 'Jane%20Doe'),
    ('Try  Alert', 'Try%20%20Alert'),
    ('Many Spaces Between Words', 'Many%20Spaces%20Between%20Words')
]


@pytest.mark.parametrize('query, encoded_query', URL_ENCODE_VALUES)
def test_url_encode(query, encoded_query):
    """

    Given:
        - A query that needed to be url encoded

    When:
        - Searching users or teams and providing a query

    Then:
        - Returns the query url encoded

    """
    assert url_encode(query) == encoded_query


FETCH_START_TIME_VALUES = [
    (None,
     '1 hour',
     dateparser.parse('2020-07-29 10:00:00 UTC').replace(tzinfo=utc, microsecond=0)),
    (None,
     '3 days',
     dateparser.parse('2020-07-26 11:00:00 UTC').replace(tzinfo=utc, microsecond=0)),
    ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
     '3 days',
     dateparser.parse('2020-07-27 11:00:00 UTC').replace(tzinfo=utc, microsecond=0)),
    ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
     '2 hours',
     dateparser.parse('2020-07-29 9:00:00 UTC').replace(tzinfo=utc, microsecond=0)),
    ('1595847600',  # epoch time for 2020-07-27 11:00:00 UTC
     '1596013200',  # epoch time for 2020-07-29 9:00:00 UTC
     dateparser.parse('2020-07-29 9:00:00 UTC').replace(tzinfo=utc, microsecond=0)),
]


@pytest.mark.parametrize('last_fetch, first_fetch, expected_output', FETCH_START_TIME_VALUES)
@freeze_time("2020-07-29 11:00:00 UTC")
def test_calculate_fetch_start_time(last_fetch, first_fetch, expected_output):
    """

    Given:
        - The last fetch time and the first fetch to fetch from

    When:
        - Fetch incidents runs

    Then:
        - Returns the time to fetch from - the latter of the 2 given

    """
    # works only with lint
    assert calculate_fetch_start_time(last_fetch, first_fetch) == expected_output


PARSE_ALERTS_VALUES = [
    (
        [
            {
                "id": 2,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 5,
                "name": "Adi's Alert",
                "state": "no_data",
                "newStateDate": "2021-07-29T14:03:20Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            },
            {
                "id": 1,
                "dashboardId": 1,
                "dashboardUid": "TXSTREZ",
                "dashboardSlug": "simple-streaming-example",
                "panelId": 4,
                "name": "Arseny's Alert",
                "state": "no_data",
                "newStateDate": "2021-06-09T15:20:01Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/TXSTREZ/simple-streaming-example"
            },
            {
                "id": 3,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 6,
                "name": "TryAlert",
                "state": "alerting",
                "newStateDate": "2021-07-08T12:08:40Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            }
        ],
        1,
        dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        ["Arseny's Alert"]
    ),
    (
        [
            {
                "id": 2,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 5,
                "name": "Adi's Alert",
                "state": "no_data",
                "newStateDate": "2021-07-29T14:03:20Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            },
            {
                "id": 1,
                "dashboardId": 1,
                "dashboardUid": "TXSTREZ",
                "dashboardSlug": "simple-streaming-example",
                "panelId": 4,
                "name": "Arseny's Alert",
                "state": "no_data",
                "newStateDate": "2021-06-09T15:20:01Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/TXSTREZ/simple-streaming-example"
            },
            {
                "id": 3,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 6,
                "name": "TryAlert",
                "state": "alerting",
                "newStateDate": "2021-07-08T12:08:40Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            }
        ],
        2,
        dateparser.parse('2020-06-08 10:00:00 UTC').replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-07-08 12:08:40 UTC').replace(tzinfo=utc, microsecond=0),
        ["Arseny's Alert", "TryAlert"]
    ),
    (
        [
            {
                "id": 2,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 5,
                "name": "Adi's Alert",
                "state": "no_data",
                "newStateDate": "2021-07-29T14:03:20Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            },
            {
                "id": 1,
                "dashboardId": 1,
                "dashboardUid": "TXSTREZ",
                "dashboardSlug": "simple-streaming-example",
                "panelId": 4,
                "name": "Arseny's Alert",
                "state": "no_data",
                "newStateDate": "2021-06-09T15:20:01Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/TXSTREZ/simple-streaming-example"
            },
            {
                "id": 3,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 6,
                "name": "TryAlert",
                "state": "alerting",
                "newStateDate": "2021-07-08T12:08:40Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            }
        ],
        2,
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
        ["TryAlert", "Adi's Alert"]
    ),
    (
        [
            {
                "id": 2,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 5,
                "name": "Adi's Alert",
                "state": "no_data",
                "newStateDate": "2021-07-29T14:03:20Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            },
            {
                "id": 1,
                "dashboardId": 1,
                "dashboardUid": "TXSTREZ",
                "dashboardSlug": "simple-streaming-example",
                "panelId": 4,
                "name": "Arseny's Alert",
                "state": "no_data",
                "newStateDate": "2021-06-09T15:20:01Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/TXSTREZ/simple-streaming-example"
            },
            {
                "id": 3,
                "dashboardId": 2,
                "dashboardUid": "yzDQUOR7z",
                "dashboardSlug": "simple-streaming-example-adis-copy",
                "panelId": 6,
                "name": "TryAlert",
                "state": "alerting",
                "newStateDate": "2021-07-08T12:08:40Z",
                "evalDate": "0001-01-01T00:00:00Z",
                "evalData": {
                    "noData": True
                },
                "executionError": "",
                "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
            }
        ],
        10,
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
        ["TryAlert", "Adi's Alert"]
    ),
    (
        [],
        5,
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        []
    )
]


@pytest.mark.parametrize('alerts, max_fetch, last_fetch, expected_output_time, expected_incidents_names', PARSE_ALERTS_VALUES)
def test_parse_alerts(alerts, max_fetch, last_fetch, expected_output_time, expected_incidents_names):
    """

    Given:
        - A list of alerts, time to fetch from

    When:
        - Fetch incidents runs

    Then:
        - Returns the new time to fetch from next time, and the incidents fetched

    """
    output = parse_alerts(alerts, max_fetch, last_fetch)
    assert output[0] == expected_output_time
    for i in range(len(expected_incidents_names)):
        assert output[1][i]['name'] == expected_incidents_names[i]


ALERT_VALUES = [
    (
        {
            "id": 2,
            "dashboardId": 2,
            "dashboardUid": "yzDQUOR7z",
            "dashboardSlug": "simple-streaming-example-adis-copy",
            "panelId": 5,
            "name": "Adi's Alert",
            "state": "no_data",
            "newStateDate": "2021-07-29T14:03:20Z",
            "evalDate": "0001-01-01T00:00:00Z",
            "evalData": {
                "noData": True
            }},
        dateparser.parse("2021-07-29T14:03:20Z").replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-06-09 15:20:01 UTC').replace(tzinfo=utc, microsecond=0),
        {
            'name': "Adi's Alert",
            'occurred': "2021-07-29T14:03:20Z",
            'type': 'Grafana Alert'
        }),
    (
        {
            "id": 2,
            "dashboardId": 2,
            "dashboardUid": "yzDQUOR7z",
            "dashboardSlug": "simple-streaming-example-adis-copy",
            "panelId": 5,
            "name": "Adi's Alert",
            "state": "no_data",
            "newStateDate": "2021-07-29T14:03:20Z",
            "evalDate": "0001-01-01T00:00:00Z",
            "evalData": {
                "noData": True
            }},
        dateparser.parse("2021-07-29T14:03:20Z").replace(tzinfo=utc, microsecond=0),
        dateparser.parse('2021-07-29 14:03:20 UTC').replace(tzinfo=utc, microsecond=0),
        None),
]


@pytest.mark.parametrize('alert, change_date, last_fetch, expected_incident', ALERT_VALUES)
def test_parse_alert(alert, change_date, last_fetch, expected_incident):
    """

    Given:
        - An alert, the time it changed at, and the time to fetch from

    When:
        - Fetch incidents runs

    Then:
        - Returns the incident

    """
    incident = parse_alert(alert, change_date, last_fetch)
    if incident:
        incident.pop('rawJSON')
    assert incident == expected_incident


CONCATENATE_URL_VALUES = [
    ('https://base_url',
     [
         {
             "id": 1,
             "dashboardId": 1,
             "dashboardUid": "TXSTREZ",
             "dashboardSlug": "simple-streaming-example",
             "panelId": 4,
             "name": "Arseny's Alert",
             "state": "no_data",
             "newStateDate": "2021-06-09T15:20:01Z",
             "evalDate": "0001-01-01T00:00:00Z",
             "evalData": {
                 "noData": True
             },
             "executionError": "",
             "url": "/d/TXSTREZ/simple-streaming-example"
         },
         {
             "id": 2,
             "dashboardId": 2,
             "dashboardUid": "yzDQUOR7z",
             "dashboardSlug": "simple-streaming-example-adis-copy",
             "panelId": 5,
             "name": "Adi's Alert",
             "state": "paused",
             "newStateDate": "2021-06-15T14:27:40.178025099Z",
             "evalDate": "0001-01-01T00:00:00Z",
             "evalData": None,
             "executionError": "",
             "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy"
         }
     ],
     [
         {
             "id": 1,
             "dashboardId": 1,
             "dashboardUid": "TXSTREZ",
             "dashboardSlug": "simple-streaming-example",
             "panelId": 4,
             "name": "Arseny's Alert",
             "state": "no_data",
             "newStateDate": "2021-06-09T15:20:01Z",
             "evalDate": "0001-01-01T00:00:00Z",
             "evalData": {
                 "noData": True
             },
             "executionError": "",
             "url": "https://base_url/d/TXSTREZ/simple-streaming-example"
         },
         {
             "id": 2,
             "dashboardId": 2,
             "dashboardUid": "yzDQUOR7z",
             "dashboardSlug": "simple-streaming-example-adis-copy",
             "panelId": 5,
             "name": "Adi's Alert",
             "state": "paused",
             "newStateDate": "2021-06-15T14:27:40.178025099Z",
             "evalDate": "0001-01-01T00:00:00Z",
             "evalData": None,
             "executionError": "",
             "url": "https://base_url/d/yzDQUOR7z/simple-streaming-example-adis-copy"
         }
     ]
     ),
    ('https://00.000.000.000:0000/',
     [
         {
             "id": 1,
             "uid": "TXSTREZ",
             "title": "Simple Streaming Example",
             "uri": "db/simple-streaming-example",
             "url": "/d/TXSTREZ/simple-streaming-example",
             "slug": "",
             "type": "dash-db",
             "tags": [],
             "isStarred": True,
             "sortMeta": 0
         },
         {
             "id": 2,
             "uid": "yzDQUOR7z",
             "title": "Simple Streaming Example - Adi's Copy",
             "uri": "db/simple-streaming-example-adis-copy",
             "url": "/d/yzDQUOR7z/simple-streaming-example-adis-copy",
             "slug": "",
             "type": "dash-db",
             "tags": [],
             "isStarred": False,
             "sortMeta": 0
         }
     ],
     [
         {
             "id": 1,
             "uid": "TXSTREZ",
             "title": "Simple Streaming Example",
             "uri": "db/simple-streaming-example",
             "url": "https://00.000.000.000:0000/d/TXSTREZ/simple-streaming-example",
             "slug": "",
             "type": "dash-db",
             "tags": [],
             "isStarred": True,
             "sortMeta": 0
         },
         {
             "id": 2,
             "uid": "yzDQUOR7z",
             "title": "Simple Streaming Example - Adi's Copy",
             "uri": "db/simple-streaming-example-adis-copy",
             "url": "https://00.000.000.000:0000/d/yzDQUOR7z/simple-streaming-example-adis-copy",
             "slug": "",
             "type": "dash-db",
             "tags": [],
             "isStarred": False,
             "sortMeta": 0
         }
     ]
     ),
    ('https://base_url',
     [
         {
             "id": 1,
             "dashboardId": 1,
             "state": "no_data",
         },
         {
             "id": 2,
             "dashboardId": 2,
             "panelId": 5,
             "state": "paused",
         }
     ],
     [
         {
             "id": 1,
             "dashboardId": 1,
             "state": "no_data",
         },
         {
             "id": 2,
             "dashboardId": 2,
             "panelId": 5,
             "state": "paused",
         }
     ]
     )
]


@pytest.mark.parametrize('base_url, dict_input, expected_result', CONCATENATE_URL_VALUES)
def test_concatenate_url(base_url, dict_input, expected_result):
    """

    Given:
        - A url entry in a dictionary, with the suffix only as value

    When:
        - A dashboard url is given

    Then:
        - Returns the dictionary with the url value as base and suffix

    """
    client = create_client(url=base_url)
    assert client._concatenate_url(dict_input) == expected_result

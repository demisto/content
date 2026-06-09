import importlib
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import dateparser
import demistomock as demisto
import ElasticsearchEventCollector
import json
import pytest

"""MOCKED RESPONSES"""

ES_V6_RESPONSE = {
    "took": 1,
    "timed_out": False,
    "_shards": {"total": 5, "successful": 5, "skipped": 0, "failed": 0},
    "hits": {
        "total": 17,
        "max_score": 1.3862944,
        "hits": [
            {
                "_index": "users",
                "_type": "_doc",
                "_id": "123",
                "_score": 1.3862944,
                "_source": {"Date": "2019-08-29T14:45:00.123Z"},
            },
            {
                "_index": "users",
                "_type": "_doc",
                "_id": "456",
                "_score": 0.9517491,
                "_source": {"Date": "2019-08-29T14:46:00.123456Z"},
            },
        ],
    },
}

ES_V7_RESPONSE = {
    "took": 1,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 9, "relation": "eq"},
        "max_score": 0.6814878,
        "hits": [
            {
                "_index": "customer",
                "_type": "doc",
                "_id": "123",
                "_score": 0.6814878,
                "_source": {"Date": "2019-08-27T18:00:00Z"},
            },
            {
                "_index": "customer",
                "_type": "doc",
                "_id": "456",
                "_score": 0.6814878,
                "_source": {"Date": "2019-08-27T18:01:25.343212Z"},
            },
        ],
    },
}


ES_V8_RESPONSE = {
    "took": 8,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 9, "relation": "eq"},
        "max_score": 0.8,
        "hits": [
            {
                "_index": "customer",
                "_type": "doc",
                "_id": "888",
                "_score": 0.8,
                "_source": {"Date": "2024-08-27T18:00:00Z"},
            },
            {
                "_index": "customer",
                "_type": "doc",
                "_id": "999",
                "_score": 0.79,
                "_source": {"Date": "2024-08-27T18:01:25.343212Z"},
            },
        ],
    },
}
# The "hits" key is missing
ES_V8_CORRUPTED_RESPONSE = {
    "took": 8,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
}


MOCK_ES7_INCIDENTS = str(
    [
        {
            "name": "Elasticsearch: Index: customer, ID: 123",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "123", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "2019-08-27T18:00:00Z"}'
            "}",
            "occurred": "2019-08-27T18:00:00Z",
            "dbotMirrorId": "123",
            "labels": [{"type": "Date", "value": "2019-08-27T18:00:00Z"}],
            "_time": "2019-08-27T18:00:00Z",
        },
        {
            "name": "Elasticsearch: Index: customer, ID: 456",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "456", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "2019-08-27T18:01:25.343212Z"}'
            "}",
            "occurred": "2019-08-27T18:01:25Z",
            "dbotMirrorId": "456",
            "labels": [{"type": "Date", "value": "2019-08-27T18:01:25.343212Z"}],
            "_time": "2019-08-27T18:01:25Z",
        },
    ]
)

MOCK_ES7_INCIDENTS_WITHOUT_LABELS = str(
    [
        {
            "name": "Elasticsearch: Index: customer, ID: 123",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "123", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "2019-08-27T18:00:00Z"}'
            "}",
            "occurred": "2019-08-27T18:00:00Z",
            "dbotMirrorId": "123",
            "_time": "2019-08-27T18:00:00Z",
        },
        {
            "name": "Elasticsearch: Index: customer, ID: 456",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "456", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "2019-08-27T18:01:25.343212Z"}'
            "}",
            "occurred": "2019-08-27T18:01:25Z",
            "dbotMirrorId": "456",
            "_time": "2019-08-27T18:01:25Z",
        },
    ]
)

MOCK_ES6_INCIDENTS = str(
    [
        {
            "name": "Elasticsearch: Index: users, ID: 123",
            "rawJSON": "{"
            '"_index": "users", '
            '"_type": "_doc", '
            '"_id": "123", '
            '"_score": 1.3862944, '
            '"_source": {"Date": "2019-08-29T14:45:00.123Z"}'
            "}",
            "occurred": "2019-08-29T14:45:00Z",
            "dbotMirrorId": "123",
            "labels": [{"type": "Date", "value": "2019-08-29T14:45:00.123Z"}],
            "_time": "2019-08-29T14:45:00Z",
        },
        {
            "name": "Elasticsearch: Index: users, ID: 456",
            "rawJSON": "{"
            '"_index": "users", '
            '"_type": "_doc", '
            '"_id": "456", '
            '"_score": 0.9517491, '
            '"_source": {"Date": "2019-08-29T14:46:00.123456Z"}'
            "}",
            "occurred": "2019-08-29T14:46:00Z",
            "dbotMirrorId": "456",
            "labels": [{"type": "Date", "value": "2019-08-29T14:46:00.123456Z"}],
            "_time": "2019-08-29T14:46:00Z",
        },
    ]
)

MOCK_ES6_INCIDENTS_WITHOUT_LABELS = str(
    [
        {
            "name": "Elasticsearch: Index: users, ID: 123",
            "rawJSON": "{"
            '"_index": "users", '
            '"_type": "_doc", '
            '"_id": "123", '
            '"_score": 1.3862944, '
            '"_source": {"Date": "2019-08-29T14:45:00.123Z"}'
            "}",
            "occurred": "2019-08-29T14:45:00Z",
            "dbotMirrorId": "123",
            "_time": "2019-08-29T14:45:00Z",
        },
        {
            "name": "Elasticsearch: Index: users, ID: 456",
            "rawJSON": "{"
            '"_index": "users", '
            '"_type": "_doc", '
            '"_id": "456", '
            '"_score": 0.9517491, '
            '"_source": {"Date": "2019-08-29T14:46:00.123456Z"}'
            "}",
            "occurred": "2019-08-29T14:46:00Z",
            "dbotMirrorId": "456",
            "_time": "2019-08-29T14:46:00Z",
        },
    ]
)

ES_V7_RESPONSE_WITH_TIMESTAMP = {
    "took": 1,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 9, "relation": "eq"},
        "max_score": 0.6814878,
        "hits": [
            {"_index": "customer", "_type": "doc", "_id": "123", "_score": 0.6814878, "_source": {"Date": "1572502634"}},
            {"_index": "customer", "_type": "doc", "_id": "456", "_score": 0.6814878, "_source": {"Date": "1572502640"}},
        ],
    },
}

MOCK_ES7_INCIDENTS_FROM_TIMESTAMP = str(
    [
        {
            "name": "Elasticsearch: Index: customer, ID: 123",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "123", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "1572502634"}'
            "}",
            "occurred": "2019-10-31T06:17:14Z",
            "dbotMirrorId": "123",
            "labels": [{"type": "Date", "value": "1572502634"}],
            "_time": "2019-10-31T06:17:14Z",
        },
        {
            "name": "Elasticsearch: Index: customer, ID: 456",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "456", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "1572502640"}'
            "}",
            "occurred": "2019-10-31T06:17:20Z",
            "dbotMirrorId": "456",
            "labels": [{"type": "Date", "value": "1572502640"}],
            "_time": "2019-10-31T06:17:20Z",
        },
    ]
)

MOCK_ES7_INCIDENTS_FROM_TIMESTAMP_WITHOUT_LABELS = str(
    [
        {
            "name": "Elasticsearch: Index: customer, ID: 123",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "123", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "1572502634"}'
            "}",
            "occurred": "2019-10-31T06:17:14Z",
            "dbotMirrorId": "123",
            "_time": "2019-10-31T06:17:14Z",
        },
        {
            "name": "Elasticsearch: Index: customer, ID: 456",
            "rawJSON": "{"
            '"_index": "customer", '
            '"_type": "doc", '
            '"_id": "456", '
            '"_score": 0.6814878, '
            '"_source": {"Date": "1572502640"}'
            "}",
            "occurred": "2019-10-31T06:17:20Z",
            "dbotMirrorId": "456",
            "_time": "2019-10-31T06:17:20Z",
        },
    ]
)


MOCK_PARAMS = [
    {
        "client_type": "Elasticsearch",
        "fetch_index": "customer",
        "fetch_time_field": "Date",
        "time_method": "Simple-Date",
        "map_labels": True,
        "credentials": {
            "identifier": "mock",
            "password": "demisto",
        },
    },
    {
        "client_type": "Elasticsearch",
        "fetch_index": "customer",
        "fetch_time_field": "Date",
        "time_method": "Simple-Date",
        "map_labels": False,
        "credentials": {
            "identifier": "mock",
            "password": "demisto",
        },
    },
    {
        "client_type": "OpenSearch",
        "fetch_index": "customer",
        "fetch_time_field": "Date",
        "time_method": "Simple-Date",
        "map_labels": True,
        "credentials": {
            "identifier": "mock",
            "password": "demisto",
        },
    },
]

PARAMS_V8 = {
    "client_type": "Elasticsearch_v8",
    "fetch_index": "customer",
    "fetch_time_field": "Date",
    "time_method": "Simple-Date",
    "map_labels": True,
    "credentials": {
        "identifier": "mock",
        "password": "demisto",
    },
}


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_e6(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    from ElasticsearchEventCollector import results_to_events_datetime

    last_fetch = "2019-08-29T14:44:00Z"
    incidents, last_fetch2, _ = results_to_events_datetime(ES_V6_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == "2019-08-29T14:46:00.123456+00:00"
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES6_INCIDENTS
    else:
        assert str(incidents) == MOCK_ES6_INCIDENTS_WITHOUT_LABELS


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_e7(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    from ElasticsearchEventCollector import results_to_events_datetime

    last_fetch = "2019-08-27T17:59:00"
    incidents, last_fetch2, _ = results_to_events_datetime(ES_V7_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == "2019-08-27T18:01:25.343212+00:00"
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES7_INCIDENTS
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_WITHOUT_LABELS


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_timestamp_to_date_converter_seconds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("ElasticsearchEventCollector.TIME_METHOD", "Timestamp-Seconds")
    from ElasticsearchEventCollector import timestamp_to_date

    seconds_since_epoch = "1572164838"
    assert str(timestamp_to_date(seconds_since_epoch)) == "2019-10-27 08:27:18"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_timestamp_to_date_converter_milliseconds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("ElasticsearchEventCollector.TIME_METHOD", "Timestamp-Milliseconds")
    from ElasticsearchEventCollector import timestamp_to_date

    milliseconds_since_epoch = "1572164838123"
    assert str(timestamp_to_date(milliseconds_since_epoch)) == "2019-10-27 08:27:18.123000"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_with_timestamp_e7(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("ElasticsearchEventCollector.TIME_METHOD", "Timestamp-Seconds")
    from ElasticsearchEventCollector import results_to_events_timestamp

    lastfetch = int(datetime.strptime("2019-08-27T17:59:00Z", "%Y-%m-%dT%H:%M:%SZ").timestamp())
    incidents, last_fetch2, _ = results_to_events_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, lastfetch)
    assert last_fetch2 == 1572502640
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP_WITHOUT_LABELS


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_format_to_iso(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    from ElasticsearchEventCollector import format_to_iso

    date_string_1 = "2020-02-03T10:00:00"
    date_string_2 = "2020-02-03T10:00:00+02:00"
    date_string_3 = "2020-02-03T10:00:00-02:00"
    iso_format = "2020-02-03T10:00:00Z"
    assert format_to_iso(date_string_1) == iso_format
    assert format_to_iso(date_string_2) == iso_format
    assert format_to_iso(date_string_3) == iso_format
    assert format_to_iso(iso_format) == iso_format


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_builder_called_with_username_password(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    from ElasticsearchEventCollector import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") == ("mock", "demisto")
    assert es_mock.call_args[1].get("api_key") is None


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_builder_called_with_no_creds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("ElasticsearchEventCollector.USERNAME", None)
    mocker.patch("ElasticsearchEventCollector.PASSWORD", None)
    from ElasticsearchEventCollector import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") is None


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_builder_called_with_cred(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(ElasticsearchEventCollector)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("ElasticsearchEventCollector.USERNAME", "username")
    mocker.patch("ElasticsearchEventCollector.PASSWORD", "password")
    mocker.patch("ElasticsearchEventCollector.AUTH_TYPE", ElasticsearchEventCollector.BASIC_AUTH)
    from ElasticsearchEventCollector import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth")[0] == "username"
    assert es_mock.call_args[1].get("http_auth")[1] == "password"
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") is None

    mocker.patch("ElasticsearchEventCollector.AUTH_TYPE", ElasticsearchEventCollector.API_KEY_AUTH)
    mocker.patch("ElasticsearchEventCollector.API_KEY", "api_key_id")
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") == "api_key_id"
    assert es_mock.call_args[1].get("bearer_auth") is None

    mocker.patch("ElasticsearchEventCollector.AUTH_TYPE", ElasticsearchEventCollector.BEARER_AUTH)
    mocker.patch("ElasticsearchEventCollector.get_elastic_token", return_value="elastic_token")
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") == "elastic_token"


# This is the class we want to test
"""
The get-mapping-fields command perform a GET /<index name>/_mapping http command
for e.g http://elasticserver.com/customers/_mapping the output is then formatted and arranged by the parse-tree function
The test created a mock response.
"""


class TestIncidentLabelMaker(unittest.TestCase):
    def test_sanity(self):
        from ElasticsearchEventCollector import event_label_maker

        sources = {
            "first_name": "John",
            "sur_name": "Snow",
        }
        expected_labels = [
            {"type": "first_name", "value": "John"},
            {"type": "sur_name", "value": "Snow"},
        ]

        labels = event_label_maker(sources)
        assert labels == expected_labels

    def test_complex_value(self):
        from ElasticsearchEventCollector import event_label_maker

        sources = {
            "name": "Ash",
            "action": "catch",
            "targets": ["Pikachu", "Charmander", "Squirtle", "Bulbasaur"],
        }
        expected_labels = [
            {
                "type": "name",
                "value": "Ash",
            },
            {
                "type": "action",
                "value": "catch",
            },
            {
                "type": "targets",
                "value": '["Pikachu", "Charmander", "Squirtle", "Bulbasaur"]',
            },
        ]

        labels = event_label_maker(sources)
        assert labels == expected_labels


@pytest.mark.parametrize(
    "time_method, last_fetch, time_range_start, time_range_end, result",
    [
        (
            "Timestamp-Milliseconds",
            "",
            "1.1.2000 12:00:00Z",
            "2.1.2000 12:00:00Z",
            {"range": {"time_field": {"gte": 946728000000, "lt": 949406400000}}},
        ),
        (
            "Timestamp-Milliseconds",
            946728000000,
            "",
            "2.1.2000 12:00:00Z",
            {"range": {"time_field": {"gte": 946728000000, "lt": 949406400000}}},
        ),
        ("Timestamp-Milliseconds", "", "", "2.1.2000 12:00:00Z", {"range": {"time_field": {"lt": 949406400000}}}),
        (
            "Simple-Date",
            "2.1.2000 12:00:00.000000",
            "",
            "",
            {
                "range": {
                    "time_field": {
                        "gte": "2.1.2000 12:00:00.000000",
                        "format": ElasticsearchEventCollector.ES_DEFAULT_DATETIME_FORMAT,
                    }
                }
            },
        ),
    ],
)
def test_get_time_range(time_method, last_fetch, time_range_start, time_range_end, result):
    from ElasticsearchEventCollector import get_time_range

    assert get_time_range(last_fetch, time_range_start, time_range_end, "time_field", time_method=time_method) == result


@pytest.mark.parametrize(
    "time_method, time_range_start, expected_time_zone",
    [
        ("Simple-Date", "2024-01-15T10:30:00+02:00", "+02:00"),
        ("Simple-Date", "2024-01-15T10:30:00-05:00", "-05:00"),
        ("Simple-Date", "2024-01-15T10:30:00+03:30", "+03:30"),
        ("Simple-Date", "2024-01-15T10:30:00-11:00", "-11:00"),
        ("Timestamp-Seconds", "2024-01-15T10:30:00+02:00", "+02:00"),
        ("Timestamp-Milliseconds", "2024-01-15T10:30:00-05:00", "-05:00"),
        ("Simple-Date", "2024-01-15T10:30:00Z", None),
        ("Simple-Date", "2024-01-15T10:30:00", None),
    ],
)
def test_get_time_range_with_utc_offset(time_method, time_range_start, expected_time_zone):
    """
    Test that UTC offset is correctly extracted from time_range_start and added to range_dict.

    Given:
        - A time_range_start with various UTC offset formats (+HH:MM or -HH:MM)
        - Different time methods (Simple-Date, Timestamp-Seconds, Timestamp-Milliseconds)

    When:
        - Calling get_time_range with the time_range_start parameter

    Then:
        - The UTC offset should be extracted and added to range_dict as 'time_zone'
        - If no UTC offset is present (Z or no offset), time_zone should not be in range_dict
    """
    from ElasticsearchEventCollector import get_time_range

    result = get_time_range(
        last_fetch=None, time_range_start=time_range_start, time_range_end=None, time_field="time_field", time_method=time_method
    )

    if expected_time_zone:
        assert "time_zone" in result["range"]["time_field"]
        assert result["range"]["time_field"]["time_zone"] == expected_time_zone
    else:
        assert "time_zone" not in result["range"]["time_field"]


@pytest.mark.parametrize(
    "raw_query_body",
    [
        ({"query": {"match": {"name": "test"}}, "size": 2, "from": 1}),
        ({"query": {"match": {"name": "test"}}, "size": 2}),
        ({"query": {"match": {"name": "test"}}, "from": 3}),
        ({"query": {"match": {"name": "test"}}}),
    ],
)
def test_execute_raw_query(mocker, raw_query_body):
    """
    Given
      - index and elastic search objects

    When
    - executing execute_raw_query function with two response: first an exception and second a correct response.

    Then
     - make sure that no exception was raised from the function.
     - make sure the response came back correctly.
    """
    import ElasticsearchEventCollector

    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "search", return_value=ES_V7_RESPONSE)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "__init__", return_value=None)
    es = ElasticsearchEventCollector.elasticsearch_builder({})
    assert (
        ElasticsearchEventCollector.execute_raw_query(es, json.dumps(raw_query_body), index="index from parameter")
        == ES_V7_RESPONSE
    )


@patch.dict("os.environ", {"DEMISTO_PARAMS": str(PARAMS_V8)})
@pytest.mark.parametrize(
    "raw_query_body",
    [
        ({"query": {"match": {"name": "test"}}, "size": 2, "from": 1}),
        ({"query": {"match": {"name": "test"}}, "size": 2}),
        ({"query": {"match": {"name": "test"}}, "from": 3}),
        ({"query": {"match": {"name": "test"}}}),
    ],
)
def test_execute_raw_query_v8(mocker, raw_query_body):
    """
    Given
      - index and elastic search objects
      - instance configured to v8

    When
    - executing execute_raw_query function with query_dsl body

    Then
     - make sure that no exception was raised from the function.
     - make sure the response came back correctly.
     - make sure the query body can be serialized an does not throw errors.
    """
    import ElasticsearchEventCollector
    from elastic_transport import RequestsHttpNode

    ElasticsearchEventCollector.RequestsHttpNode = RequestsHttpNode

    class CustomExecute:
        def to_dict():  # type: ignore
            return ES_V8_RESPONSE

    mocker.patch.object(ElasticsearchEventCollector, "ELASTIC_SEARCH_CLIENT", ElasticsearchEventCollector.ELASTICSEARCH_V8)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "search", return_value=ES_V7_RESPONSE)
    mocker.patch.object(ElasticsearchEventCollector.Search, "execute", return_value=CustomExecute)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "__init__", return_value=None)
    mocker.patch.object(RequestsHttpNode, "__init__", return_value=None)

    es = ElasticsearchEventCollector.elasticsearch_builder({})
    assert ElasticsearchEventCollector.execute_raw_query(es, json.dumps(raw_query_body), index="") == ES_V8_RESPONSE


@pytest.mark.parametrize(
    "date_time, time_method, expected_time",
    [
        ("123456", "Timestamp-Seconds", 123456),
        ("123456", "Timestamp-Milliseconds", 123456),
        (dateparser.parse("July 1, 2023"), "Simple-Date", "2023-07-01 00:00:00.000000"),
        (dateparser.parse("2023-07-01 23:24:25.123456"), "Simple-Date", "2023-07-01 23:24:25.123456"),
    ],
)
def test_convert_date_to_timestamp(date_time, time_method, expected_time):
    """
    Given
      - A python datetime object.
      - The time_method parameter ('Timestamp-Seconds', 'Timestamp-Milliseconds', 'Simple-Date').

    When
        - Executing convert_date_to_timestamp function.

    Then
        - Make sure that the returned datetime is as expected with the correct format.
    """
    assert ElasticsearchEventCollector.convert_date_to_timestamp(date_time, time_method=time_method) == expected_time


def test_get_value_by_dot_notation():
    """
    GIVEN a dictionary and a key in dot notation
    WHEN get_value_by_dot_notation is called
    THEN it should return the value corresponding to the key
    """
    dictionary = {"a": {"b": {"c": 123}}, "x": {"y": 456}}
    key = "a.b.c"

    result = ElasticsearchEventCollector.get_value_by_dot_notation(dictionary, key)

    assert result == 123


def test_key_not_found():
    """
    GIVEN a dictionary and a key in dot notation that does not exist
    WHEN get_value_by_dot_notation is called
    THEN it should return None
    """
    dictionary = {"a": {"b": True}, "x": {"y": 456}}
    key = "a.b.d"  # Key 'a.b.d' does not exist

    result = ElasticsearchEventCollector.get_value_by_dot_notation(dictionary, key)

    assert result is None


@pytest.mark.parametrize(
    "server_details, server_version, client_version",
    [
        (
            {
                "name": "test1",
                "cluster_name": "elasticsearch",
                "cluster_uuid": "test_id",
                "version": {
                    "number": "7.3.0",
                },
            },
            "7.3.0",
            "Elasticsearch_v8",
        ),
        (
            {
                "name": "test2",
                "cluster_name": "elasticsearch",
                "cluster_uuid": "test_id",
                "version": {
                    "number": "8.4.1",
                },
            },
            "8.4.1",
            "Elasticsearch",
        ),
    ],
    ids=[
        "Test miss configuration error - server version is 7 while client version is 8",
        "Test miss configuration error - server version is 8 while client version is 7",
    ],
)
def test_verify_es_server_version_errors(mocker, server_details, server_version, client_version):
    """
    Tests the 'verify_es_server_version' function's logic.

    Given
      1. Elastic search server details (response json of the requests.get) - server version is 7.3.0.
         Integration parameter - client type - is set to 'Elasticsearch_v8.
      2. Elastic search server details (response json of the requests.get) - server version is 8.4.1.
         Integration parameter - client type - is set to 'Elasticsearch. (v7 and below)

    When
    - Running the verify_es_server_version function.

    Then
     - Make sure that the expected error message is raised.
    """
    import ElasticsearchEventCollector

    mocker.patch("ElasticsearchEventCollector.ELASTIC_SEARCH_CLIENT", new=client_version)
    with pytest.raises(ValueError) as e:
        ElasticsearchEventCollector.verify_es_server_version(server_details)
    assert server_version in str(e.value)


class TestGetElasticToken:
    """Tests for the get_elastic_token function."""

    @pytest.fixture
    def mock_integration_context(self, mocker):
        """Fixture to mock integration context functions."""
        mock_get = mocker.patch("ElasticsearchEventCollector.get_integration_context")
        mock_set = mocker.patch("ElasticsearchEventCollector.set_integration_context")
        return mock_get, mock_set

    @pytest.fixture
    def mock_requests_post(self, mocker):
        """Fixture to mock requests.post."""
        return mocker.patch("ElasticsearchEventCollector.requests.post")

    def test_get_elastic_token_existing_valid_token(self, mocker, mock_integration_context):
        """
        Given:
            - An existing valid access token in integration context that hasn't expired
        When:
            - Calling get_elastic_token
        Then:
            - Return the existing access token without making any API calls
        """
        import ElasticsearchEventCollector

        mock_get, mock_set = mock_integration_context
        future_time = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = {
            "access_token": "existing_valid_token",
            "access_token_expires_in": future_time,
            "refresh_token": "refresh_token",
            "refresh_token_expires_in": future_time,
        }

        mocker.patch("ElasticsearchEventCollector.USERNAME", "test_user")
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "test_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        result = ElasticsearchEventCollector.get_elastic_token()

        assert result == "existing_valid_token"

    def test_get_elastic_token_expired_token_valid_refresh(self, mocker, mock_integration_context, mock_requests_post):
        """
        Given:
            - An expired access token but a valid refresh token in integration context
        When:
            - Calling get_elastic_token
        Then:
            - Use the refresh token to get a new access token
            - Update the integration context with new tokens
            - Return the new access token
        """
        import ElasticsearchEventCollector

        mock_get, mock_set = mock_integration_context
        past_time = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_time = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = {
            "access_token": "expired_token",
            "access_token_expires_in": past_time,
            "refresh_token": "valid_refresh_token",
            "refresh_token_expires_in": future_time,
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }
        mock_requests_post.return_value = mock_response

        mocker.patch("ElasticsearchEventCollector.USERNAME", "test_user")
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "test_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        result = ElasticsearchEventCollector.get_elastic_token()

        assert result == "new_access_token"
        assert mock_requests_post.call_count == 1
        call_args = mock_requests_post.call_args
        assert call_args[1]["json"]["grant_type"] == "refresh_token"
        assert call_args[1]["json"]["refresh_token"] == "valid_refresh_token"

    def test_get_elastic_token_password_grant(self, mocker, mock_integration_context, mock_requests_post):
        """
        Given:
            - No existing tokens or expired refresh token
        When:
            - Calling get_elastic_token
        Then:
            - Perform password grant authentication
            - Store new tokens in integration context
            - Return the new access token
        """
        import ElasticsearchEventCollector

        mock_get, mock_set = mock_integration_context
        mock_get.return_value = {}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "password_grant_token",
            "refresh_token": "password_grant_refresh",
            "expires_in": 3600,
        }
        mock_requests_post.return_value = mock_response

        mocker.patch("ElasticsearchEventCollector.USERNAME", "test_user")
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "test_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        result = ElasticsearchEventCollector.get_elastic_token()

        assert result == "password_grant_token"
        assert mock_requests_post.call_count == 1
        call_args = mock_requests_post.call_args
        assert call_args[1]["json"]["grant_type"] == "password"
        assert call_args[1]["json"]["username"] == "test_user"
        assert call_args[1]["json"]["password"] == "test_pass"

    def test_get_elastic_token_missing_credentials(self, mocker, mock_integration_context):
        """
        Given:
            - Missing username or password
        When:
            - Calling get_elastic_token
        Then:
            - Raise DemistoException with appropriate error message
        """
        import ElasticsearchEventCollector
        from CommonServerPython import DemistoException

        mock_get, mock_set = mock_integration_context
        mock_get.return_value = {}

        mocker.patch("ElasticsearchEventCollector.USERNAME", None)
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "test_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        with pytest.raises(DemistoException) as exc_info:
            ElasticsearchEventCollector.get_elastic_token()

        assert "username or password fields are missing" in str(exc_info.value)

    def test_get_elastic_token_refresh_fails_fallback_to_password(self, mocker, mock_integration_context, mock_requests_post):
        """
        Given:
            - Expired access token and valid refresh token
            - Refresh token request fails
        When:
            - Calling get_elastic_token
        Then:
            - Attempt refresh token flow first
            - Fall back to password grant when refresh fails
            - Return new access token from password grant
        """
        import ElasticsearchEventCollector

        mock_get, mock_set = mock_integration_context
        past_time = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        future_time = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = {
            "access_token": "expired_token",
            "access_token_expires_in": past_time,
            "refresh_token": "valid_refresh_token",
            "refresh_token_expires_in": future_time,
        }

        # First call (refresh) fails, second call (password grant) succeeds
        mock_refresh_response = MagicMock()
        mock_refresh_response.status_code = 401

        mock_password_response = MagicMock()
        mock_password_response.status_code = 200
        mock_password_response.json.return_value = {
            "access_token": "new_password_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }

        mock_requests_post.side_effect = [mock_refresh_response, mock_password_response]

        mocker.patch("ElasticsearchEventCollector.USERNAME", "test_user")
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "test_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        result = ElasticsearchEventCollector.get_elastic_token()

        assert result == "new_password_token"
        assert mock_requests_post.call_count == 2
        # Verify first call was refresh token
        assert mock_requests_post.call_args_list[0][1]["json"]["grant_type"] == "refresh_token"
        # Verify second call was password grant
        assert mock_requests_post.call_args_list[1][1]["json"]["grant_type"] == "password"

    def test_get_elastic_token_authentication_failure(self, mocker, mock_integration_context, mock_requests_post):
        """
        Given:
            - No existing tokens
            - Password grant authentication fails
        When:
            - Calling get_elastic_token
        Then:
            - Raise DemistoException with authentication failure message
        """
        import ElasticsearchEventCollector
        from CommonServerPython import DemistoException

        mock_get, mock_set = mock_integration_context
        mock_get.return_value = {}

        mock_response = MagicMock()
        mock_response.status_code = 401
        reason = "unable to authenticate user [test_user] for REST request [/_security/oauth2/token]"
        mock_response.text = json.dumps({"error": {"reason": reason}})
        mock_requests_post.return_value = mock_response

        mocker.patch("ElasticsearchEventCollector.USERNAME", "test_user")
        mocker.patch("ElasticsearchEventCollector.PASSWORD", "wrong_pass")
        mocker.patch("ElasticsearchEventCollector.SERVER", "http://test-server")
        mocker.patch("ElasticsearchEventCollector.INSECURE", True)

        with pytest.raises(DemistoException) as exc_info:
            ElasticsearchEventCollector.get_elastic_token()

        assert reason in str(exc_info.value)


def test_results_to_events_datetime_exact_timestamp_boundary(mocker):
    """Test event deduplication at exact timestamp boundaries"""
    mocker.patch("ElasticsearchEventCollector.TIME_FIELD", "Date")
    mocker.patch("ElasticsearchEventCollector.MAP_LABELS", True)
    from ElasticsearchEventCollector import results_to_events_datetime

    response = {
        "hits": {
            "total": {"value": 2, "relation": "eq"},
            "hits": [
                {"_index": "test", "_id": "id1", "_source": {"Date": "2024-01-01T10:00:00Z"}},
                {"_index": "test", "_id": "id2", "_source": {"Date": "2024-01-01T10:00:01Z"}},
                {"_index": "test", "_id": "id3", "_source": {"Date": "2024-01-01T10:00:02Z"}},
                {"_index": "test", "_id": "id4", "_source": {"Date": "2024-01-01T10:00:03Z"}},
            ],
        }
    }

    # No events seen yet
    last_fetch = "2024-01-01T10:00:01Z"
    events, _, _ = results_to_events_datetime(response, last_fetch)

    assert len(events) == 3
    fetched_ids = [json.loads(event["rawJSON"])["_id"] for event in events]
    assert "id2" in fetched_ids
    assert "id3" in fetched_ids
    assert "id4" in fetched_ids

    # event id2 is already seen, filtered out.
    last_fetch = "2024-01-01T10:00:01Z"
    events, _, _ = results_to_events_datetime(response, last_fetch, seen_event_ids=["id2"])
    fetched_ids = [json.loads(event["rawJSON"])["_id"] for event in events]
    assert len(events) == 2
    assert "id3" in fetched_ids
    assert "id4" in fetched_ids


def test_fetch_events_with_api_failure(mocker):
    """Test fetch_events with API failures, response is missing the hits key"""

    from ElasticsearchEventCollector import fetch_events

    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "search", return_value=ES_V8_CORRUPTED_RESPONSE)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "__init__", return_value=None)
    es = ElasticsearchEventCollector.elasticsearch_builder({})
    mocker.patch("ElasticsearchEventCollector.ELASTIC_SEARCH_CLIENT", "Elasticsearch_v8")
    mocker.patch("ElasticsearchEventCollector.elasticsearch_builder", return_value=es)

    with pytest.raises(Exception) as exc_info:
        fetch_events({})

    assert "AttributeError" in str(exc_info.type)


def test_fetch_events_interrupted(mocker):
    """Test fetch_events with interrupted fetch by send_events_to_xsiam raise exception"""

    from ElasticsearchEventCollector import fetch_events

    mock_set_last_run = mocker.patch("ElasticsearchEventCollector.demisto.setLastRun")

    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "search", return_value=ES_V8_RESPONSE)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "__init__", return_value=None)
    es = ElasticsearchEventCollector.elasticsearch_builder({})
    mocker.patch("ElasticsearchEventCollector.ELASTIC_SEARCH_CLIENT", "Elasticsearch_v8")
    mocker.patch("ElasticsearchEventCollector.elasticsearch_builder", return_value=es)

    # Make send_events_to_xsiam raise an exception
    mocker.patch("ElasticsearchEventCollector.send_events_to_xsiam", side_effect=Exception("Network error"))

    with pytest.raises(Exception) as exc_info:
        fetch_events({})

    assert "Network error" in str(exc_info.value)
    # Verify last run was not updated
    assert mock_set_last_run.call_count == 0


def test_get_events_with_parameters(mocker):
    """Test get_events command with all parameter combinations"""

    from ElasticsearchEventCollector import get_events

    mocker.patch(
        "ElasticsearchEventCollector.demisto.args",
        return_value={
            "raw_query": "",
            "fetch_query": "status:active",
            "fetch_time_field": "Date",
            "fetch_index": "test-index",
            "fetch_size": "10",
            "time_method": "Simple-Date",
            "start_time": "2024-01-01T00:00:00Z",
            "end_time": "2025-01-01T00:00:00Z",
        },
    )

    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "search", return_value=ES_V8_RESPONSE)
    mocker.patch.object(ElasticsearchEventCollector.Elasticsearch, "__init__", return_value=None)
    es = ElasticsearchEventCollector.elasticsearch_builder({})
    mocker.patch("ElasticsearchEventCollector.ELASTIC_SEARCH_CLIENT", "Elasticsearch_v8")
    mocker.patch("ElasticsearchEventCollector.elasticsearch_builder", return_value=es)

    result = get_events({})
    assert "999" in result.readable_output
    assert "888" in result.readable_output

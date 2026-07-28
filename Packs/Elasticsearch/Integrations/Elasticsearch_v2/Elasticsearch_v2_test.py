import importlib
import unittest
from datetime import datetime, timedelta
from unittest import mock
from unittest.mock import patch, MagicMock

import dateparser
import demistomock as demisto
import Elasticsearch_v2
import json
import pytest
import requests

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


MOCK_ES7_SEARCH_CONTEXT = str(
    {
        "Server": "",
        "Index": "customer",
        "Query": "check",
        "Page": 0,
        "Size": 2,
        "total": {"value": 9, "relation": "eq"},
        "max_score": 0.6814878,
        "took": 1,
        "timed_out": False,
        "Results": [
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
    }
)

MOCK_ES7_HIT_CONTEXT = str(
    [
        {"_index": "customer", "_id": "123", "_type": "doc", "_score": 0.6814878, "Date": "2019-08-27T18:00:00Z"},
        {"_index": "customer", "_id": "456", "_type": "doc", "_score": 0.6814878, "Date": "2019-08-27T18:01:25.343212Z"},
    ]
)

MOCK_ES6_SEARCH_CONTEXT = str(
    {
        "Server": "",
        "Index": "users",
        "Query": "incident",
        "Page": 0,
        "Size": 2,
        "total": {"value": 17},
        "max_score": 1.3862944,
        "took": 1,
        "timed_out": False,
        "Results": [
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
    }
)

MOCK_ES6_HIT_CONTEXT = str(
    [
        {"_index": "users", "_id": "123", "_type": "_doc", "_score": 1.3862944, "Date": "2019-08-29T14:45:00.123Z"},
        {"_index": "users", "_id": "456", "_type": "_doc", "_score": 0.9517491, "Date": "2019-08-29T14:46:00.123456Z"},
    ]
)

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
        },
    ]
)

MOCK_ES6_INCIDETNS = str(
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
        },
    ]
)

MOCK_ES6_INCIDETNS_WITHOUT_LABELS = str(
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
        },
    ]
)

MOCK_ES7_SCHEMA_INPUT = {"bytes": {"type": "long"}, "clientip": {"type": "ip"}}

MOCK_ES7_SCHEMA_OUTPUT = {"bytes": "type: long", "clientip": "type: ip"}

MOC_ES7_SERVER_RESPONSE = {
    "kibana_sample_data_logs": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "alias", "path": "timestamp"},
                "agent": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "bytes": {"type": "long"},
                "clientip": {"type": "ip"},
                "event": {"properties": {"dataset": {"type": "keyword"}}},
                "extension": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "geo": {
                    "properties": {
                        "coordinates": {"type": "geo_point"},
                        "dest": {"type": "keyword"},
                        "src": {"type": "keyword"},
                        "srcdest": {"type": "keyword"},
                    }
                },
                "host": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "index": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "ip": {"type": "ip"},
                "machine": {
                    "properties": {
                        "os": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                        "ram": {"type": "long"},
                    }
                },
                "memory": {"type": "double"},
                "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "phpmemory": {"type": "long"},
                "referer": {"type": "keyword"},
                "request": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "response": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "tags": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "timestamp": {"type": "date"},
                "url": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "utc_time": {"type": "date"},
            }
        }
    }
}

MOCK_INDEX_RESPONSE = {
    "_index": "test-index",
    "_id": "1",
    "_version": 1,
    "result": "created",
    "_shards": {"total": 2, "successful": 2, "failed": 0},
    "_seq_no": 5,
    "_primary_term": 1,
}

MOCK_INDICES_STATISTICS_RESPONSE = {
    "index_name1": {"uuid": "1111", "health": "yellow", "status": "open", "total": {"docs": {"count": 2, "deleted": 0}}},
    "index_name2": {"uuid": "2222", "health": "green", "status": "closed", "total": {"docs": {"count": 40, "deleted": 2}}},
}

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
def test_context_creation_es7(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import get_total_results, results_to_context

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V7_RESPONSE)
    query = "check"
    index = "customer"
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(
        index, query, base_page, size, total_dict, ES_V7_RESPONSE
    )

    assert str(search_context) == MOCK_ES7_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size', 'aggregations']"
    assert str(hit_tables) == MOCK_ES7_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_context_creation_es6(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import get_total_results, results_to_context

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V6_RESPONSE)
    query = "incident"
    index = "users"
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(
        index, query, base_page, size, total_dict, ES_V6_RESPONSE
    )

    assert str(search_context) == MOCK_ES6_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size', 'aggregations']"
    assert str(hit_tables) == MOCK_ES6_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_e6(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_incidents_datetime

    last_fetch = "2019-08-29T14:44:00Z"
    incidents, last_fetch2, _ = results_to_incidents_datetime(ES_V6_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == "2019-08-29T14:46:00.123456+00:00"
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES6_INCIDETNS
    else:
        assert str(incidents) == MOCK_ES6_INCIDETNS_WITHOUT_LABELS


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_e7(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_incidents_datetime

    last_fetch = "2019-08-27T17:59:00"
    incidents, last_fetch2, _ = results_to_incidents_datetime(ES_V7_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == "2019-08-27T18:01:25.343212+00:00"
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES7_INCIDENTS
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_WITHOUT_LABELS


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_timestamp_to_date_converter_seconds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("Elasticsearch_v2.TIME_METHOD", "Timestamp-Seconds")
    from Elasticsearch_v2 import timestamp_to_date

    seconds_since_epoch = "1572164838"
    assert str(timestamp_to_date(seconds_since_epoch)) == "2019-10-27 08:27:18"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_timestamp_to_date_converter_milliseconds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("Elasticsearch_v2.TIME_METHOD", "Timestamp-Milliseconds")
    from Elasticsearch_v2 import timestamp_to_date

    milliseconds_since_epoch = "1572164838123"
    assert str(timestamp_to_date(milliseconds_since_epoch)) == "2019-10-27 08:27:18.123000"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_incident_creation_with_timestamp_e7(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("Elasticsearch_v2.TIME_METHOD", "Timestamp-Seconds")
    from Elasticsearch_v2 import results_to_incidents_timestamp

    lastfetch = int(datetime.strptime("2019-08-27T17:59:00Z", "%Y-%m-%dT%H:%M:%SZ").timestamp())
    incidents, last_fetch2, _ = results_to_incidents_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, lastfetch)
    assert last_fetch2 == 1572502640
    if params.get("map_labels"):
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP_WITHOUT_LABELS


# XSUP-72750: three documents sharing an identical sub-second timestamp at the fetch boundary.
ES_IDENTICAL_TIMESTAMP_RESPONSE = {
    "took": 1,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 3, "relation": "eq"},
        "max_score": 1.0,
        "hits": [
            {"_index": "customer", "_type": "doc", "_id": "a1", "_source": {"Date": "2019-08-27T18:00:00.120000Z"}},
            {"_index": "customer", "_type": "doc", "_id": "a2", "_source": {"Date": "2019-08-27T18:00:00.120000Z"}},
            {"_index": "customer", "_type": "doc", "_id": "a3", "_source": {"Date": "2019-08-27T18:00:00.120000Z"}},
        ],
    },
}


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_datetime_identical_timestamps_no_data_loss_across_fetches(params, mocker):
    """
    XSUP-72750 regression test (Simple-Date / datetime path).

    Given:
        - Three documents that share an identical sub-second timestamp which is the
          fetch high-water-mark, split across two fetch cycles (first fetch returns
          only 'a1', second fetch returns all three because the query lower bound is now inclusive).
    When:
        - Running results_to_incidents_datetime twice, feeding the returned last_fetch and
          last_fetch_ids from the first call into the second (mimicking demisto.setLastRun/getLastRun).
    Then:
        - All three documents are ingested exactly once (no data loss, no duplicates).
    """
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)
    from Elasticsearch_v2 import results_to_incidents_datetime

    first_response = {"hits": {"hits": [ES_IDENTICAL_TIMESTAMP_RESPONSE["hits"]["hits"][0]]}}

    # First fetch: only 'a1' is available (page boundary cuts the rest off).
    incidents1, last_fetch1, ids1 = results_to_incidents_datetime(first_response, "2019-08-27T17:59:00Z")
    assert [inc["dbotMirrorId"] for inc in incidents1] == ["a1"]
    assert ids1 == ["a1"]

    # Second fetch: query is now gte the boundary timestamp, so all three are returned.
    incidents2, last_fetch2, ids2 = results_to_incidents_datetime(ES_IDENTICAL_TIMESTAMP_RESPONSE, last_fetch1, ids1)
    # 'a1' must be skipped (already ingested), 'a2' and 'a3' must be ingested.
    assert [inc["dbotMirrorId"] for inc in incidents2] == ["a2", "a3"]
    assert sorted(ids2) == ["a1", "a2", "a3"]

    # Overall: all three ingested exactly once.
    all_ingested = [inc["dbotMirrorId"] for inc in incidents1 + incidents2]
    assert sorted(all_ingested) == ["a1", "a2", "a3"]


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_datetime_identical_timestamps_no_duplicates_on_replay(params, mocker):
    """
    XSUP-72750 regression test (Simple-Date / datetime path) - idempotency.

    Given:
        - A fetch that already ingested all three identically-timestamped documents.
    When:
        - The exact same response is returned again (e.g. no new documents arrived).
    Then:
        - No incidents are produced (all skipped by _id de-duplication), so no duplicates.
    """
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)
    from Elasticsearch_v2 import results_to_incidents_datetime

    incidents1, last_fetch1, ids1 = results_to_incidents_datetime(ES_IDENTICAL_TIMESTAMP_RESPONSE, "2019-08-27T17:59:00Z")
    assert sorted(inc["dbotMirrorId"] for inc in incidents1) == ["a1", "a2", "a3"]

    # Replay the same response with the persisted state.
    incidents2, last_fetch2, ids2 = results_to_incidents_datetime(ES_IDENTICAL_TIMESTAMP_RESPONSE, last_fetch1, ids1)
    assert incidents2 == []
    assert sorted(ids2) == ["a1", "a2", "a3"]


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_timestamp_identical_timestamps_no_data_loss_across_fetches(params, mocker):
    """
    XSUP-72750 regression test (Timestamp path).

    Given:
        - Three documents that share an identical epoch-millisecond timestamp which is the
          fetch high-water-mark, split across two fetch cycles.
    When:
        - Running results_to_incidents_timestamp twice, feeding the returned last_fetch and
          last_fetch_ids from the first call into the second.
    Then:
        - All three documents are ingested exactly once (no data loss, no duplicates).
    """
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)
    mocker.patch("Elasticsearch_v2.TIME_METHOD", "Timestamp-Milliseconds")
    from Elasticsearch_v2 import results_to_incidents_timestamp

    ts = 1566928800120  # 2019-08-27T18:00:00.120Z in epoch milliseconds
    hit = {"_index": "customer", "_type": "doc", "_source": {"Date": ts}}
    response = {
        "hits": {
            "hits": [
                {**hit, "_id": "a1"},
                {**hit, "_id": "a2"},
                {**hit, "_id": "a3"},
            ]
        }
    }
    first_response = {"hits": {"hits": [{**hit, "_id": "a1"}]}}

    last_fetch = 1566928740000  # earlier than ts
    incidents1, last_fetch1, ids1 = results_to_incidents_timestamp(first_response, last_fetch)
    assert [inc["dbotMirrorId"] for inc in incidents1] == ["a1"]
    assert last_fetch1 == ts
    assert ids1 == ["a1"]

    incidents2, last_fetch2, ids2 = results_to_incidents_timestamp(response, last_fetch1, ids1)
    assert [inc["dbotMirrorId"] for inc in incidents2] == ["a2", "a3"]
    assert last_fetch2 == ts
    assert sorted(ids2) == ["a1", "a2", "a3"]


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_datetime_identical_timestamps_boundary_ids_persist_over_three_fetches(params, mocker):
    """
    XSUP-72750 regression test - continuity over three fetch cycles.

    Given:
        - Three documents sharing an identical boundary timestamp, revealed one per fetch.
    When:
        - Running results_to_incidents_datetime three times, always feeding back the persisted
          last_fetch and last_fetch_ids (mimicking demisto.getLastRun/setLastRun).
    Then:
        - Each document is ingested exactly once and the boundary id set never drifts,
          so no document is ever re-ingested as a duplicate on a later cycle.
    """
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)
    from Elasticsearch_v2 import results_to_incidents_datetime

    hits = ES_IDENTICAL_TIMESTAMP_RESPONSE["hits"]["hits"]
    fetch1 = {"hits": {"hits": hits[:1]}}
    fetch2 = {"hits": {"hits": hits[:2]}}
    fetch3 = {"hits": {"hits": hits[:3]}}

    incidents1, last_fetch, ids = results_to_incidents_datetime(fetch1, "2019-08-27T17:59:00Z")
    incidents2, last_fetch, ids = results_to_incidents_datetime(fetch2, last_fetch, ids)
    incidents3, last_fetch, ids = results_to_incidents_datetime(fetch3, last_fetch, ids)

    assert [inc["dbotMirrorId"] for inc in incidents1] == ["a1"]
    assert [inc["dbotMirrorId"] for inc in incidents2] == ["a2"]
    assert [inc["dbotMirrorId"] for inc in incidents3] == ["a3"]
    assert sorted(ids) == ["a1", "a2", "a3"]

    all_ingested = [inc["dbotMirrorId"] for inc in incidents1 + incidents2 + incidents3]
    assert sorted(all_ingested) == ["a1", "a2", "a3"]


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_datetime_newer_timestamp_resets_boundary_ids(params, mocker):
    """
    XSUP-72750 regression test - boundary id reset when a newer timestamp appears.

    Given:
        - A page containing some documents at the boundary timestamp and some at a strictly
          newer timestamp.
    When:
        - Running results_to_incidents_datetime with the boundary id already persisted.
    Then:
        - The previously-fetched boundary id is skipped, new documents are ingested, and the
          returned boundary id set contains only the ids at the new (newer) high-water-mark.
    """
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)
    from Elasticsearch_v2 import results_to_incidents_datetime

    response = {
        "hits": {
            "hits": [
                {"_index": "c", "_type": "doc", "_id": "a1", "_source": {"Date": "2019-08-27T18:00:00.120000Z"}},
                {"_index": "c", "_type": "doc", "_id": "a2", "_source": {"Date": "2019-08-27T18:00:00.120000Z"}},
                {"_index": "c", "_type": "doc", "_id": "b1", "_source": {"Date": "2019-08-27T18:05:00.500000Z"}},
            ]
        }
    }

    # 'a1' was already ingested at the previous boundary (18:00:00.120000).
    incidents, last_fetch, ids = results_to_incidents_datetime(response, "2019-08-27T18:00:00.120000Z", ["a1"])

    # 'a1' skipped, 'a2' and 'b1' ingested; the boundary advanced to b1's timestamp,
    # so only 'b1' remains as the boundary id.
    assert [inc["dbotMirrorId"] for inc in incidents] == ["a2", "b1"]
    assert ids == ["b1"]


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_format_to_iso(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import format_to_iso

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
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") == ("mock", "demisto")
    assert es_mock.call_args[1].get("api_key") is None


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_builder_called_with_no_creds(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("Elasticsearch_v2.USERNAME", None)
    mocker.patch("Elasticsearch_v2.PASSWORD", None)
    from Elasticsearch_v2 import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") is None


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_builder_called_with_cred(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch("Elasticsearch_v2.USERNAME", "username")
    mocker.patch("Elasticsearch_v2.PASSWORD", "password")
    mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.BASIC_AUTH)
    from Elasticsearch_v2 import Elasticsearch, elasticsearch_builder

    es_mock = mocker.patch.object(Elasticsearch, "__init__", return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth")[0] == "username"
    assert es_mock.call_args[1].get("http_auth")[1] == "password"
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") is None

    mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.API_KEY_AUTH)
    mocker.patch("Elasticsearch_v2.API_KEY", "api_key_id")
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") == "api_key_id"
    assert es_mock.call_args[1].get("bearer_auth") is None

    mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.BEARER_AUTH)
    mocker.patch("Elasticsearch_v2.get_elastic_token", return_value="elastic_token")
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get("http_auth") is None
    assert es_mock.call_args[1].get("api_key") is None
    assert es_mock.call_args[1].get("bearer_auth") == "elastic_token"


@pytest.mark.parametrize("params", MOCK_PARAMS)
def test_elasticsearch_parse_subtree(params, mocker):
    mocker.patch.object(demisto, "params", return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import parse_subtree

    sub_tree = parse_subtree(MOCK_ES7_SCHEMA_INPUT)
    assert str(sub_tree) == str(MOCK_ES7_SCHEMA_OUTPUT)


# This is the class we want to test
"""
The get-mapping-fields command perform a GET /<index name>/_mapping http command
for e.g http://elasticserver.com/customers/_mapping the output is then formatted and arranged by the parse-tree function
The test created a mock response.
"""


class GetMapping:
    def fetch_json(self, url):
        response = requests.get(url)
        return response.json()


# This method will be used by the mock to replace requests.get
@patch("Elasticsearch_v2.FETCH_INDEX", "customer")
def mocked_requests_get(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if args[0] == "http://someurl.com/" + "index" + "/_mapping":
        return MockResponse(MOC_ES7_SERVER_RESPONSE, 200)
    else:
        return MockResponse(None, 404)


# Our test case class
class GetMappingFields(unittest.TestCase):
    # We patch 'requests.get' with our own method. The mock object is passed in to our test case method.
    @mock.patch("requests.get", side_effect=mocked_requests_get)
    def test_fetch(self, mock_get):
        # Assert requests.get calls
        gmf = GetMapping()
        server_response = gmf.fetch_json("http://someurl.com/" + "index" + "/_mapping")
        assert server_response == MOC_ES7_SERVER_RESPONSE


class TestIncidentLabelMaker(unittest.TestCase):
    def test_sanity(self):
        from Elasticsearch_v2 import incident_label_maker

        sources = {
            "first_name": "John",
            "sur_name": "Snow",
        }
        expected_labels = [
            {"type": "first_name", "value": "John"},
            {"type": "sur_name", "value": "Snow"},
        ]

        labels = incident_label_maker(sources)
        assert labels == expected_labels

    def test_complex_value(self):
        from Elasticsearch_v2 import incident_label_maker

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

        labels = incident_label_maker(sources)
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
            {"range": {"time_field": {"gte": "2.1.2000 12:00:00.000000", "format": Elasticsearch_v2.ES_DEFAULT_DATETIME_FORMAT}}},
        ),
    ],
)
def test_get_time_range(time_method, last_fetch, time_range_start, time_range_end, result):
    Elasticsearch_v2.TIME_METHOD = time_method
    from Elasticsearch_v2 import get_time_range

    assert get_time_range(last_fetch, time_range_start, time_range_end, "time_field") == result


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
    Elasticsearch_v2.TIME_METHOD = time_method
    from Elasticsearch_v2 import get_time_range

    result = get_time_range(last_fetch=None, time_range_start=time_range_start, time_range_end=None, time_field="time_field")

    if expected_time_zone:
        assert "time_zone" in result["range"]["time_field"]
        assert result["range"]["time_field"]["time_zone"] == expected_time_zone
    else:
        assert "time_zone" not in result["range"]["time_field"]


def test_build_eql_body():
    from Elasticsearch_v2 import build_eql_body

    assert build_eql_body(None, None, None, None, None, None, None) == {}
    assert build_eql_body("query", "fields", "size", "tiebreaker_field", "timestamp_field", "event_category_field", "filter") == {
        "query": "query",
        "fields": "fields",
        "size": "size",
        "tiebreaker_field": "tiebreaker_field",
        "timestamp_field": "timestamp_field",
        "event_category_field": "event_category_field",
        "filter": "filter",
    }


first_case_all_with_empty_string = (
    "",
    {"a": {"mappings": {"properties": {"example": {}}}}},
    {"a": {"_id": "doc_id", "_index": "a", "_source": {"example": "type: "}}},
)
second_case_with_prefix_and_wildcard = (
    ".internal.alerts-*",
    {
        ".internal.alerts-security": {"mappings": {"properties": {"example": {}}}},
        ".internal": {"mappings": {"properties": {"example": {}}}},
    },
    {".internal.alerts-security": {"_id": "doc_id", "_index": ".internal.alerts-security", "_source": {"example": "type: "}}},
)
third_regular_case = (
    "a",
    {"a": {"mappings": {"properties": {"example": {}}}}},
    {"a": {"_id": "doc_id", "_index": "a", "_source": {"example": "type: "}}},
)


@pytest.mark.parametrize(
    "indexes, response, expected_result",
    [first_case_all_with_empty_string, second_case_with_prefix_and_wildcard, third_regular_case],
)
def test_get_mapping_fields_command(mocker, indexes, response, expected_result):
    class ResponseMockObject:
        def json(self):
            return response

    mocker.patch("Elasticsearch_v2.FETCH_INDEX", indexes)
    mocker.patch("Elasticsearch_v2.requests.get", return_value=ResponseMockObject())
    result = Elasticsearch_v2.get_mapping_fields_command()
    assert result == expected_result


def test_search_command_with_query_dsl(mocker):
    """
    Given
      - index to the search command with query_dsl

    When
    - executing the search command

    Then
     - make sure that the index is being taken from the command arguments and not from integration parameters
     - make sure that the size / page arguments are getting applied when using query_dsl
    """
    import Elasticsearch_v2

    Elasticsearch_v2.FETCH_INDEX = "index from parameter"
    index_from_arg = "index from arg"
    mocker.patch.object(
        demisto,
        "args",
        return_value={"index": index_from_arg, "query_dsl": '{"query": {"match": {"name": "test"}}}', "size": "5", "page": "0"},
    )
    search_mock = mocker.patch.object(Elasticsearch_v2.Elasticsearch, "search", return_value=ES_V7_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    Elasticsearch_v2.search_command({})
    assert search_mock.call_args.kwargs["index"] == [index_from_arg]
    assert search_mock.call_args.kwargs["body"] == {"query": {"match": {"name": "test"}}, "size": 5, "from": 0}


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
    import Elasticsearch_v2

    Elasticsearch_v2.FETCH_INDEX = "index from parameter"
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "search", return_value=ES_V7_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    es = Elasticsearch_v2.elasticsearch_builder({})
    assert Elasticsearch_v2.execute_raw_query(es, json.dumps(raw_query_body)) == ES_V7_RESPONSE


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
    import Elasticsearch_v2
    from elastic_transport import RequestsHttpNode

    Elasticsearch_v2.RequestsHttpNode = RequestsHttpNode

    class CustomExecute:
        def to_dict():  # type: ignore
            return ES_V8_RESPONSE

    mocker.patch.object(Elasticsearch_v2, "ELASTIC_SEARCH_CLIENT", Elasticsearch_v2.ELASTICSEARCH_V8)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "search", return_value=ES_V7_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Search, "execute", return_value=CustomExecute)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    mocker.patch.object(RequestsHttpNode, "__init__", return_value=None)

    es = Elasticsearch_v2.elasticsearch_builder({})
    assert Elasticsearch_v2.execute_raw_query(es, json.dumps(raw_query_body)) == ES_V8_RESPONSE


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
    Elasticsearch_v2.TIME_METHOD = time_method
    assert Elasticsearch_v2.convert_date_to_timestamp(date_time) == expected_time


def test_index_document(mocker):
    """
    Given
      - index name, document in JSON format, id of document

    When
    - executing index_document function.

    Then
     - Make sure that the returned function response is as expected with the correct format
    """
    import Elasticsearch_v2

    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "index", return_value=MOCK_INDEX_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    assert Elasticsearch_v2.index_document({"index_name": "test-index", "document": "{}", "id": "1"}, "") == MOCK_INDEX_RESPONSE


def test_index_document_command(mocker):
    """
    Given
      - index name, document in JSON format, id of document

    When
    - executing index_document_command function.

    Then
     - Make sure that the returned function response is as expected with the correct format
    """
    import Elasticsearch_v2

    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "index", return_value=MOCK_INDEX_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    command_result = Elasticsearch_v2.index_document_command({"index_name": "test-index", "document": "{}", "id": "1"}, "")
    expected_index_context = {
        "id": MOCK_INDEX_RESPONSE.get("_id", ""),
        "index": MOCK_INDEX_RESPONSE.get("_index", ""),
        "version": MOCK_INDEX_RESPONSE.get("_version", ""),
        "result": MOCK_INDEX_RESPONSE.get("result", ""),
    }
    expected_human_readable = (
        "### Indexed document\n|ID|Index name|Version|Result|\n|---|---|---|---|\n| 1 | test-index | 1 | created |\n"
    )

    assert command_result.outputs == expected_index_context
    assert command_result.readable_output == expected_human_readable
    assert command_result.outputs_prefix == "Elasticsearch.Index"
    assert command_result.raw_response == MOCK_INDEX_RESPONSE
    assert command_result.outputs_key_field == "id"


def test_get_value_by_dot_notation():
    """
    GIVEN a dictionary and a key in dot notation
    WHEN get_value_by_dot_notation is called
    THEN it should return the value corresponding to the key
    """
    dictionary = {"a": {"b": {"c": 123}}, "x": {"y": 456}}
    key = "a.b.c"

    result = Elasticsearch_v2.get_value_by_dot_notation(dictionary, key)

    assert result == 123


def test_key_not_found():
    """
    GIVEN a dictionary and a key in dot notation that does not exist
    WHEN get_value_by_dot_notation is called
    THEN it should return None
    """
    dictionary = {"a": {"b": True}, "x": {"y": 456}}
    key = "a.b.d"  # Key 'a.b.d' does not exist

    result = Elasticsearch_v2.get_value_by_dot_notation(dictionary, key)

    assert result is None


@pytest.mark.parametrize(
    "limit, all_results, expected_context",
    [
        (
            1,
            True,
            [
                {
                    "Name": "index_name1",
                    "Status": "open",
                    "Health": "yellow",
                    "UUID": "1111",
                    "Documents Count": 2,
                    "Documents Deleted": 0,
                },
                {
                    "Name": "index_name2",
                    "Status": "closed",
                    "Health": "green",
                    "UUID": "2222",
                    "Documents Count": 40,
                    "Documents Deleted": 2,
                },
            ],
        ),
        (
            1,
            False,
            [
                {
                    "Name": "index_name1",
                    "Status": "open",
                    "Health": "yellow",
                    "UUID": "1111",
                    "Documents Count": 2,
                    "Documents Deleted": 0,
                }
            ],
        ),
    ],
    ids=[
        "Test get indices statistics with a limit and all_results=True",
        "Test get indices statistics with a limit and all_results=False",
    ],
)
def test_get_indices_statistics_command(mocker, limit, all_results, expected_context):
    """
    Tests the 'get_indices_statistics' integration command.
    Given
      1. Elastic search client, a limit of 1, all_results arg set to True.
      2. Elastic search client, a limit of 1, all_results arg set to False.

    When
    - Running the get_indices_statistics_command function.

    Then
     - Make sure that the returned function response includes the indices mocked data as expected:
        1. All results were returned (2 indices).
        2. Only the first index's data was returned.
    """
    import Elasticsearch_v2

    mocker.patch.object(Elasticsearch_v2, "get_indices_statistics", return_value=MOCK_INDICES_STATISTICS_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, "__init__", return_value=None)
    command_result = Elasticsearch_v2.get_indices_statistics_command({"limit": limit, "all_results": all_results}, "")

    assert command_result.outputs == expected_context
    assert "Indices Statistics:" in command_result.readable_output
    assert command_result.outputs_prefix == "Elasticsearch.IndexStatistics"
    assert command_result.raw_response == MOCK_INDICES_STATISTICS_RESPONSE
    assert command_result.outputs_key_field == "UUID"


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
    import Elasticsearch_v2

    mocker.patch("Elasticsearch_v2.ELASTIC_SEARCH_CLIENT", new=client_version)
    with pytest.raises(ValueError) as e:
        Elasticsearch_v2.verify_es_server_version(server_details)
    assert server_version in str(e.value)


def test_search_command_with_query_esql(mocker):
    """
    Given
      - query to the search command with esql

    When
    - executing the es-esql-search command

    Then
     - Make sure that the expected message is returned.
    """
    MOCKER_RES = {"columns": [{"name": "col_1"}, {"name": "col_2"}], "values": [["val_1", "val_2"], ["val_1_1", "val_2_2"]]}
    EXPECTED_HEADERS = {
        "Content-Type": "application/vnd.elasticsearch+json; compatible-with=9",
        "Accept": "application/vnd.elasticsearch+json; compatible-with=9",
    }
    magic_mock = MagicMock()
    magic_mock.body = MOCKER_RES
    magic_mock.__getitem__.side_effect = lambda key: magic_mock.body[key]

    import Elasticsearch_v2

    mocked_builder = mocker.patch.object(Elasticsearch_v2, "elasticsearch_builder")
    mocked_builder().perform_request.return_value = magic_mock
    mocker.patch.object(Elasticsearch_v2, "ELASTIC_SEARCH_CLIENT", new=Elasticsearch_v2.ELASTICSEARCH_V9)

    query = """FROM alerts | WHERE alertDetails.alertuser LIKE "*karl*"| KEEP *"""
    res = Elasticsearch_v2.search_esql_command({"query": query, "limit": 2}, {})

    call_args = mocked_builder().perform_request.call_args[1]
    assert res.outputs_prefix == "Elasticsearch.ESQLSearch"
    assert res.outputs == [{"col_1": "val_1", "col_2": "val_2"}, {"col_1": "val_1_1", "col_2": "val_2_2"}]
    assert res.raw_response == magic_mock.body
    assert call_args["headers"] == EXPECTED_HEADERS
    assert call_args["body"] == {"query": f"{query}| LIMIT 2"}


class TestGetElasticToken:
    """Tests for the get_elastic_token function."""

    @pytest.fixture
    def mock_integration_context(self, mocker):
        """Fixture to mock integration context functions."""
        mock_get = mocker.patch("Elasticsearch_v2.get_integration_context")
        mock_set = mocker.patch("Elasticsearch_v2.set_integration_context")
        return mock_get, mock_set

    @pytest.fixture
    def mock_requests_post(self, mocker):
        """Fixture to mock requests.post."""
        return mocker.patch("Elasticsearch_v2.requests.post")

    def test_get_elastic_token_existing_valid_token(self, mocker, mock_integration_context):
        """
        Given:
            - An existing valid access token in integration context that hasn't expired
        When:
            - Calling get_elastic_token
        Then:
            - Return the existing access token without making any API calls
        """
        import Elasticsearch_v2

        mock_get, mock_set = mock_integration_context
        future_time = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        mock_get.return_value = {
            "access_token": "existing_valid_token",
            "access_token_expires_in": future_time,
            "refresh_token": "refresh_token",
            "refresh_token_expires_in": future_time,
        }

        mocker.patch("Elasticsearch_v2.USERNAME", "test_user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "test_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        result = Elasticsearch_v2.get_elastic_token()

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
        import Elasticsearch_v2

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

        mocker.patch("Elasticsearch_v2.USERNAME", "test_user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "test_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        result = Elasticsearch_v2.get_elastic_token()

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
        import Elasticsearch_v2

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

        mocker.patch("Elasticsearch_v2.USERNAME", "test_user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "test_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        result = Elasticsearch_v2.get_elastic_token()

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
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mock_get, mock_set = mock_integration_context
        mock_get.return_value = {}

        mocker.patch("Elasticsearch_v2.USERNAME", None)
        mocker.patch("Elasticsearch_v2.PASSWORD", "test_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_elastic_token()

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
        import Elasticsearch_v2

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

        mocker.patch("Elasticsearch_v2.USERNAME", "test_user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "test_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        result = Elasticsearch_v2.get_elastic_token()

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
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mock_get, mock_set = mock_integration_context
        mock_get.return_value = {}

        mock_response = MagicMock()
        mock_response.status_code = 401
        reason = "unable to authenticate user [test_user] for REST request [/_security/oauth2/token]"
        mock_response.text = json.dumps({"error": {"reason": reason}})
        mock_requests_post.return_value = mock_response

        mocker.patch("Elasticsearch_v2.USERNAME", "test_user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "wrong_pass")
        mocker.patch("Elasticsearch_v2.SERVER", "http://test-server")
        mocker.patch("Elasticsearch_v2.INSECURE", True)

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_elastic_token()

        assert reason in str(exc_info.value)


class TestGetKibanaBaseUrl:
    """Tests for the get_kibana_base_url function."""

    def test_get_kibana_base_url_success(self, mocker):
        """
        Given:
            - A Server URL containing the ".es." Elastic Cloud subdomain segment
        When:
            - Calling get_kibana_base_url
        Then:
            - Return the URL with ".es." replaced by ".kb."
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.SERVER", "https://my-deployment-af38b6.es.us-central1.gcp.cloud.es.io")

        result = Elasticsearch_v2.get_kibana_base_url()

        assert result == "https://my-deployment-af38b6.kb.us-central1.gcp.cloud.es.io"

    def test_get_kibana_base_url_missing_es_segment(self, mocker):
        """
        Given:
            - A Server URL that does not contain the ".es." segment
        When:
            - Calling get_kibana_base_url
        Then:
            - Raise a DemistoException explaining the Kibana URL could not be derived
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mocker.patch("Elasticsearch_v2.SERVER", "https://on-prem-elastic.example.com:9200")

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_kibana_base_url()

        assert "Could not derive the Kibana URL" in str(exc_info.value)


class TestGetKibanaAuthHeaders:
    """Tests for the get_kibana_auth_headers function."""

    def test_api_key_auth(self, mocker):
        """
        Given:
            - Auth type is API key auth
        When:
            - Calling get_kibana_auth_headers
        Then:
            - Return an Authorization header built from the API key
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.API_KEY_AUTH)
        mocker.patch("Elasticsearch_v2.API_KEY", ("id123", "secret456"))

        headers = Elasticsearch_v2.get_kibana_auth_headers()

        assert headers["Authorization"].startswith("ApiKey ")

    def test_bearer_auth(self, mocker):
        """
        Given:
            - Auth type is Bearer auth
        When:
            - Calling get_kibana_auth_headers
        Then:
            - Return an Authorization header built from the elastic OAuth token
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.BEARER_AUTH)
        mocker.patch("Elasticsearch_v2.get_elastic_token", return_value="my-token")

        headers = Elasticsearch_v2.get_kibana_auth_headers()

        assert headers["Authorization"] == "Bearer my-token"

    def test_basic_auth(self, mocker):
        """
        Given:
            - Auth type is Basic auth with username and password configured
        When:
            - Calling get_kibana_auth_headers
        Then:
            - Return a Basic Authorization header
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.BASIC_AUTH)
        mocker.patch("Elasticsearch_v2.USERNAME", "user")
        mocker.patch("Elasticsearch_v2.PASSWORD", "pass")

        headers = Elasticsearch_v2.get_kibana_auth_headers()

        assert headers["Authorization"].startswith("Basic ")

    def test_missing_credentials_raises(self, mocker):
        """
        Given:
            - Auth type is Basic auth but username/password are missing
        When:
            - Calling get_kibana_auth_headers
        Then:
            - Raise a DemistoException
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mocker.patch("Elasticsearch_v2.AUTH_TYPE", Elasticsearch_v2.BASIC_AUTH)
        mocker.patch("Elasticsearch_v2.USERNAME", None)
        mocker.patch("Elasticsearch_v2.PASSWORD", None)

        with pytest.raises(DemistoException):
            Elasticsearch_v2.get_kibana_auth_headers()


class TestBuildKibanaPath:
    """Tests for the build_kibana_path function."""

    def test_without_space_id(self):
        import Elasticsearch_v2

        assert Elasticsearch_v2.build_kibana_path("/api/cases") == "/api/cases"

    def test_without_leading_slash(self):
        import Elasticsearch_v2

        assert Elasticsearch_v2.build_kibana_path("api/cases") == "/api/cases"

    def test_with_space_id(self):
        import Elasticsearch_v2

        assert Elasticsearch_v2.build_kibana_path("/api/cases", space_id="my-space") == "/s/my-space/api/cases"


class TestKibanaHttpRequest:
    """Tests for the kibana_http_request function."""

    @pytest.fixture(autouse=True)
    def setup(self, mocker):
        mocker.patch("Elasticsearch_v2.SERVER", "https://my-deployment.es.us-central1.gcp.cloud.es.io")
        mocker.patch("Elasticsearch_v2.get_kibana_auth_headers", return_value={"Authorization": "Basic dXNlcjpwYXNz"})
        mocker.patch("Elasticsearch_v2.INSECURE", True)
        mocker.patch("Elasticsearch_v2.TIMEOUT", 60)
        mocker.patch("Elasticsearch_v2.DEFAULT_SPACE_ID", "")

    def test_get_request_success(self, mocker):
        """
        Given:
            - A successful GET response from Kibana
        When:
            - Calling kibana_http_request
        Then:
            - Return the parsed JSON response
        """
        import Elasticsearch_v2

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"id": "123"}'
        mock_response.json.return_value = {"id": "123"}
        mock_request = mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        result = Elasticsearch_v2.kibana_http_request("GET", "/api/cases/123")

        assert result == {"id": "123"}
        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["url"] == "https://my-deployment.kb.us-central1.gcp.cloud.es.io/api/cases/123"
        assert "kbn-xsrf" not in call_kwargs["headers"]

    def test_post_request_adds_xsrf_header(self, mocker):
        """
        Given:
            - A POST request to Kibana
        When:
            - Calling kibana_http_request
        Then:
            - The kbn-xsrf header is added to the request
        """
        import Elasticsearch_v2

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"{}"
        mock_response.json.return_value = {}
        mock_request = mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        Elasticsearch_v2.kibana_http_request("POST", "/api/cases", json_data={"title": "test"})

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["headers"]["kbn-xsrf"] == "true"
        assert call_kwargs["json"] == {"title": "test"}

    def test_space_id_prefixes_path(self, mocker):
        """
        Given:
            - A space_id argument
        When:
            - Calling kibana_http_request
        Then:
            - The request URL includes the "/s/{space_id}" prefix
        """
        import Elasticsearch_v2

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"{}"
        mock_response.json.return_value = {}
        mock_request = mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        Elasticsearch_v2.kibana_http_request("GET", "/api/cases", space_id="my-space")

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["url"] == "https://my-deployment.kb.us-central1.gcp.cloud.es.io/s/my-space/api/cases"

    def test_default_space_id_used_when_not_provided(self, mocker):
        """
        Given:
            - No explicit space_id argument, but a configured DEFAULT_SPACE_ID
        When:
            - Calling kibana_http_request
        Then:
            - The request URL includes the default space prefix
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.DEFAULT_SPACE_ID", "default-space")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"{}"
        mock_response.json.return_value = {}
        mock_request = mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        Elasticsearch_v2.kibana_http_request("GET", "/api/cases")

        call_kwargs = mock_request.call_args[1]
        assert "/s/default-space/api/cases" in call_kwargs["url"]

    def test_error_status_code_raises(self, mocker):
        """
        Given:
            - A Kibana response with a non-ok status code and a JSON error body
        When:
            - Calling kibana_http_request
        Then:
            - Raise a DemistoException containing the error message
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.content = b'{"message": "Case not found"}'
        mock_response.json.return_value = {"message": "Case not found"}
        mock_response.text = '{"message": "Case not found"}'
        mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.kibana_http_request("GET", "/api/cases/unknown")

        assert "Case not found" in str(exc_info.value)

    def test_connection_error_raises_demisto_exception(self, mocker):
        """
        Given:
            - requests.request raises a connection error
        When:
            - Calling kibana_http_request
        Then:
            - Raise a DemistoException
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mocker.patch("Elasticsearch_v2.requests.request", side_effect=requests.exceptions.ConnectionError("boom"))

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.kibana_http_request("GET", "/api/cases")

        assert "Failed connecting to Kibana" in str(exc_info.value)

    def test_empty_response_returns_empty_dict(self, mocker):
        """
        Given:
            - A 204 No Content response
        When:
            - Calling kibana_http_request
        Then:
            - Return an empty dict
        """
        import Elasticsearch_v2

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""
        mocker.patch("Elasticsearch_v2.requests.request", return_value=mock_response)

        result = Elasticsearch_v2.kibana_http_request("DELETE", "/api/cases/123")

        assert result == {}


class TestGetJsonBodyFromEntryId:
    """Tests for the get_json_body_from_entry_id function."""

    def test_valid_json_file(self, mocker, tmp_path):
        """
        Given:
            - An entry_id pointing to a valid JSON file
        When:
            - Calling get_json_body_from_entry_id
        Then:
            - Return the parsed JSON content
        """
        import Elasticsearch_v2

        file_path = tmp_path / "body.json"
        file_path.write_text(json.dumps({"title": "test case"}))
        mocker.patch("Elasticsearch_v2.demisto.getFilePath", return_value={"path": str(file_path), "name": "body.json"})

        result = Elasticsearch_v2.get_json_body_from_entry_id("123@abc")

        assert result == {"title": "test case"}

    def test_invalid_json_raises(self, mocker, tmp_path):
        """
        Given:
            - An entry_id pointing to a file with invalid JSON content
        When:
            - Calling get_json_body_from_entry_id
        Then:
            - Raise a DemistoException
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        file_path = tmp_path / "body.json"
        file_path.write_text("not valid json")
        mocker.patch("Elasticsearch_v2.demisto.getFilePath", return_value={"path": str(file_path), "name": "body.json"})

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_json_body_from_entry_id("123@abc")

        assert "does not contain valid JSON" in str(exc_info.value)

    def test_missing_file_path_raises(self, mocker):
        """
        Given:
            - demisto.getFilePath returns no path
        When:
            - Calling get_json_body_from_entry_id
        Then:
            - Raise a DemistoException
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mocker.patch("Elasticsearch_v2.demisto.getFilePath", return_value={})

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_json_body_from_entry_id("bad-entry-id")

        assert "Could not resolve file path" in str(exc_info.value)

    def test_get_file_path_exception_raises(self, mocker):
        """
        Given:
            - demisto.getFilePath raises an exception (e.g. entry not found)
        When:
            - Calling get_json_body_from_entry_id
        Then:
            - Raise a DemistoException
        """
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        mocker.patch("Elasticsearch_v2.demisto.getFilePath", side_effect=Exception("not found"))

        with pytest.raises(DemistoException) as exc_info:
            Elasticsearch_v2.get_json_body_from_entry_id("bad-entry-id")

        assert "Failed to retrieve file info" in str(exc_info.value)


MOCK_KIBANA_CASE = {
    "id": "case-id-1",
    "title": "Test Case",
    "description": "A test case",
    "owner": "cases",
    "severity": "medium",
    "status": "open",
    "created_at": "2024-01-01T00:00:00.000Z",
    "connector": {"type": ".none"},
}


class TestBuildCaseConnector:
    """Tests for build_case_connector and build_case_connector_fields."""

    def test_raw_connector_fields_json_string_takes_precedence(self):
        import Elasticsearch_v2

        args = {
            "connector_id": "conn1",
            "connector_fields": '{"custom": "value"}',
            "connector_fields_priority_jira": "High",
        }
        connector = Elasticsearch_v2.build_case_connector(args)

        assert connector["fields"] == {"custom": "value"}
        assert connector["id"] == "conn1"

    def test_flattened_jira_fields(self):
        import Elasticsearch_v2

        args = {
            "connector_type": ".jira",
            "connector_fields_issue_type_jira": "Bug",
            "connector_fields_priority_jira": "High",
        }
        connector = Elasticsearch_v2.build_case_connector(args)

        assert connector["type"] == ".jira"
        assert connector["fields"] == {"issueType": "Bug", "priority": "High"}

    def test_servicenow_boolean_fields(self):
        import Elasticsearch_v2

        args = {
            "connector_type": ".servicenow",
            "connector_fields_dest_ip_servicenow": "true",
            "connector_fields_malware_hash_servicenow": "false",
        }
        connector = Elasticsearch_v2.build_case_connector(args)

        assert connector["fields"] == {"destIp": True, "malwareHash": False}

    def test_no_connector_args_returns_none(self):
        import Elasticsearch_v2

        assert Elasticsearch_v2.build_case_connector({}) is None


class TestBuildCaseBody:
    """Tests for build_case_body."""

    def test_builds_basic_fields(self):
        import Elasticsearch_v2

        args = {"title": "My Case", "description": "desc", "owner": "cases", "severity": "high", "tags": "a,b"}
        body = Elasticsearch_v2.build_case_body(args)

        assert body["title"] == "My Case"
        assert body["owner"] == "cases"
        assert body["tags"] == ["a", "b"]

    def test_require_owner_raises_when_missing(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.build_case_body({"title": "x"}, require_owner=True)

    def test_assignees_built_from_uid_list(self):
        import Elasticsearch_v2

        body = Elasticsearch_v2.build_case_body({"assignee_uid": "uid1,uid2"})

        assert body["assignees"] == [{"uid": "uid1"}, {"uid": "uid2"}]

    def test_settings_built_from_sync_and_extract(self):
        import Elasticsearch_v2

        body = Elasticsearch_v2.build_case_body({"sync_alerts": "true", "extract_observables": "false"})

        assert body["settings"] == {"syncAlerts": True, "extractObservables": False}


class TestEsKibanaCaseCreateCommand:
    """Tests for es_kibana_case_create_command."""

    def test_create_case_success(self, mocker):
        """
        Given:
            - Arguments to create a Kibana case
        When:
            - Calling es_kibana_case_create_command
        Then:
            - POST /api/cases is called and a CommandResults with the case data is returned
        """
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_KIBANA_CASE)

        result = Elasticsearch_v2.es_kibana_case_create_command(
            {"title": "Test Case", "owner": "cases", "description": "A test case"}, {}
        )

        assert result.outputs == MOCK_KIBANA_CASE
        assert result.outputs_prefix == "Elasticsearch.Kibana.Case"
        assert result.outputs_key_field == "id"
        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/cases"

    def test_create_case_with_entry_id_overrides_args(self, mocker):
        """
        Given:
            - An entry_id argument along with other case arguments
        When:
            - Calling es_kibana_case_create_command
        Then:
            - The JSON body from the file is used instead of the individual arguments
        """
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.get_json_body_from_entry_id", return_value={"title": "From File"})
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_KIBANA_CASE)

        Elasticsearch_v2.es_kibana_case_create_command({"entry_id": "123@abc", "title": "Ignored"}, {})

        call_args = mock_request.call_args
        assert call_args[1]["json_data"] == {"title": "From File"}

    def test_create_case_missing_owner_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_create_command({"title": "Test Case"}, {})


class TestEsKibanaCaseUpdateCommand:
    """Tests for es_kibana_case_update_command."""

    def test_update_case_success(self, mocker):
        """
        Given:
            - case_id, version and fields to update
        When:
            - Calling es_kibana_case_update_command
        Then:
            - PATCH /api/cases is called with a "cases" array payload
        """
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=[MOCK_KIBANA_CASE])

        result = Elasticsearch_v2.es_kibana_case_update_command({"case_id": "case-id-1", "version": "v1", "status": "closed"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "PATCH"
        payload = call_args[1]["json_data"]
        assert payload["cases"][0]["id"] == "case-id-1"
        assert payload["cases"][0]["version"] == "v1"
        assert payload["cases"][0]["status"] == "closed"
        assert result.outputs == MOCK_KIBANA_CASE

    def test_update_case_missing_case_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_update_command({"version": "v1"}, {})

    def test_update_case_missing_version_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_update_command({"case_id": "case-id-1"}, {})


class TestEsKibanaCaseDeleteCommand:
    """Tests for es_kibana_case_delete_command."""

    def test_delete_case_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_case_delete_command({"case_id": "case-id-1,case-id-2"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "DELETE"
        assert "case-id-1" in result.readable_output
        assert "case-id-2" in result.readable_output

    def test_delete_case_missing_case_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_delete_command({}, {})


class TestEsKibanaCaseListCommand:
    """Tests for es_kibana_case_list_command."""

    def test_list_by_case_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_KIBANA_CASE)

        result = Elasticsearch_v2.es_kibana_case_list_command({"case_id": "case-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/cases/case-id-1"
        assert result.outputs == [MOCK_KIBANA_CASE]

    def test_list_search(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"cases": [MOCK_KIBANA_CASE]})

        result = Elasticsearch_v2.es_kibana_case_list_command({"status": "open", "page": "1", "size": "20"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/cases/_find"
        assert call_args[1]["params"]["status"] == "open"
        assert call_args[1]["params"]["perPage"] == "20"
        assert result.outputs == [MOCK_KIBANA_CASE]


class TestEsKibanaCaseAlertsListCommand:
    """Tests for es_kibana_case_alerts_list_command."""

    def test_list_alerts_success(self, mocker):
        import Elasticsearch_v2

        alerts = [{"id": "alert-1", "index": "idx1", "attached_at": "2024-01-01T00:00:00.000Z"}]
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=alerts)

        result = Elasticsearch_v2.es_kibana_case_alerts_list_command({"case_id": "case-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/cases/case-id-1/alerts"
        assert result.outputs == alerts
        assert result.outputs_prefix == "Elasticsearch.Kibana.Case.case-id-1.Alert"

    def test_missing_case_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_alerts_list_command({}, {})


class TestEsKibanaCaseCommentCommands:
    """Tests for es_kibana_case_comment_add_command, update_command, and delete_command."""

    def test_comment_add_user_type(self, mocker):
        import Elasticsearch_v2

        response = {
            "id": "case-id-1",
            "comments": [{"comment": "hello", "created_by": {"username": "bob"}}],
        }
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=response)

        result = Elasticsearch_v2.es_kibana_case_comment_add_command(
            {"case_id": "case-id-1", "owner": "cases", "type": "user", "comment": "hello"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/cases/case-id-1/comments"
        assert call_args[1]["json_data"]["comment"] == "hello"
        assert result.outputs == response

    def test_comment_add_alert_type(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"id": "case-id-1", "comments": []})

        Elasticsearch_v2.es_kibana_case_comment_add_command(
            {"case_id": "case-id-1", "owner": "securitySolution", "type": "alert", "alert_id": "a1", "index": "i1"}, {}
        )

        call_args = mock_request.call_args
        body = call_args[1]["json_data"]
        assert body["alertId"] == "a1"
        assert body["index"] == "i1"

    def test_comment_add_missing_type_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_comment_add_command({"case_id": "case-id-1", "owner": "cases"}, {})

    def test_comment_update_success(self, mocker):
        import Elasticsearch_v2

        response = {
            "id": "case-id-1",
            "comments": [{"id": "comment-1", "comment": "updated", "updated_by": {"username": "bob"}}],
        }
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=response)

        result = Elasticsearch_v2.es_kibana_case_comment_update_command(
            {
                "case_id": "case-id-1",
                "owner": "cases",
                "type": "user",
                "comment": "updated",
                "comment_id": "comment-1",
                "version": "v1",
            },
            {},
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "PATCH"
        assert call_args[1]["json_data"]["id"] == "comment-1"
        assert result.outputs == response

    def test_comment_delete_success(self, mocker):
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_case_comment_delete_command({"case_id": "case-id-1"}, {})

        assert "case-id-1" in result.readable_output

    def test_comment_delete_missing_case_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_comment_delete_command({}, {})


class TestEsKibanaCaseFileAttachCommand:
    """Tests for es_kibana_case_file_attach_command."""

    def test_attach_file_success(self, mocker, tmp_path):
        import Elasticsearch_v2

        file_path = tmp_path / "report.pdf"
        file_path.write_bytes(b"%PDF-1.4 fake content")
        mocker.patch("Elasticsearch_v2.demisto.getFilePath", return_value={"path": str(file_path), "name": "report.pdf"})
        response = {"id": "case-id-1", "comments": [{"updated_by": {"username": "bob"}}]}
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=response)

        result = Elasticsearch_v2.es_kibana_case_file_attach_command({"case_id": "case-id-1", "entry_id": "123@abc"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/cases/case-id-1/files"
        assert "files" in call_args[1]
        assert result.outputs == response

    def test_attach_file_missing_case_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_file_attach_command({"entry_id": "123@abc"}, {})

    def test_attach_file_missing_entry_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_case_file_attach_command({"case_id": "case-id-1"}, {})


MOCK_ALERTING_HEALTH_RESPONSE = {
    "is_sufficiently_secure": True,
    "has_permanent_encryption_key": True,
    "alerting_framework_health": {
        "decryption_health": {"status": "ok"},
        "execution_health": {"status": "ok"},
        "read_health": {"status": "ok"},
    },
}

MOCK_RULE = {
    "id": "rule-id-1",
    "enabled": True,
    "name": "Test Rule",
    "rule_type_id": ".index-threshold",
    "created_at": "2024-01-01T00:00:00.000Z",
}


class TestEsKibanaAlertingHealthGetCommand:
    """Tests for es_kibana_alerting_health_get_command."""

    def test_get_health_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_ALERTING_HEALTH_RESPONSE)

        result = Elasticsearch_v2.es_kibana_alerting_health_get_command({}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "/api/alerting/_health"
        assert result.outputs == MOCK_ALERTING_HEALTH_RESPONSE
        assert result.outputs_prefix == "Elasticsearch.Kibana.AlertingHealth"
        assert "Is sufficiently secure" in result.readable_output


class TestEsKibanaRuleTypesListCommand:
    """Tests for es_kibana_rule_types_list_command."""

    def test_list_rule_types_success(self, mocker):
        import Elasticsearch_v2

        rule_types = [{"id": "type1", "name": "Type 1", "category": "cat", "producer": "prod", "action_groups": [{"id": "ag1"}]}]
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=rule_types)

        result = Elasticsearch_v2.es_kibana_rule_types_list_command({}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule_types"
        assert result.outputs == rule_types
        assert result.outputs_prefix == "Elasticsearch.Kibana.RuleTypes"


class TestEsKibanaRuleListCommand:
    """Tests for es_kibana_rule_list_command."""

    def test_list_by_rule_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_RULE)

        result = Elasticsearch_v2.es_kibana_rule_list_command({"rule_id": "rule-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1"
        assert result.outputs == [MOCK_RULE]

    def test_list_search(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_RULE]})

        result = Elasticsearch_v2.es_kibana_rule_list_command({"search": "test", "page": "1", "size": "10"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rules/_find"
        assert call_args[1]["params"]["search"] == "test"
        assert result.outputs == [MOCK_RULE]


class TestEsKibanaRuleEnableDisableCommands:
    """Tests for es_kibana_rule_enable_command and es_kibana_rule_disable_command."""

    def test_enable_rule_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_rule_enable_command({"rule_id": "rule-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/_enable"
        assert "rule-id-1" in result.readable_output
        assert "enabled" in result.readable_output

    def test_enable_rule_missing_rule_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_rule_enable_command({}, {})

    def test_disable_rule_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_rule_disable_command({"rule_id": "rule-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/_disable"
        assert "disabled" in result.readable_output

    def test_disable_rule_missing_rule_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_rule_disable_command({}, {})


class TestBuildRuleUpdateBody:
    """Tests for build_rule_update_body."""

    def test_basic_fields(self):
        import Elasticsearch_v2

        body = Elasticsearch_v2.build_rule_update_body({"name": "New name", "schedule_interval": "5m"})

        assert body["name"] == "New name"
        assert body["schedule"] == {"interval": "5m"}

    def test_flapping_fields_merged(self):
        import Elasticsearch_v2

        body = Elasticsearch_v2.build_rule_update_body(
            {"flapping_enabled": "true", "flapping_look_back_window": "5", "flapping_status_change_threshold": "3"}
        )

        assert body["flapping"] == {"enabled": True, "look_back_window": 5, "status_change_threshold": 3}

    def test_artifacts_fields(self):
        import Elasticsearch_v2

        body = Elasticsearch_v2.build_rule_update_body(
            {"artifacts_dashboards_id": "d1,d2", "artifacts_investigation_guide_blob": "guide text"}
        )

        assert body["artifacts"]["dashboards"] == [{"id": "d1"}, {"id": "d2"}]
        assert body["artifacts"]["investigation_guide"] == {"blob": "guide text"}


class TestEsKibanaRuleUpdateCommand:
    """Tests for es_kibana_rule_update_command."""

    def test_update_rule_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_RULE)

        result = Elasticsearch_v2.es_kibana_rule_update_command({"rule_id": "rule-id-1", "name": "Updated"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1"
        assert call_args[1]["json_data"] == {"name": "Updated"}
        assert result.outputs == MOCK_RULE
        assert "rule-id-1" in result.readable_output

    def test_update_rule_with_entry_id(self, mocker):
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.get_json_body_from_entry_id", return_value={"name": "From File"})
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_RULE)

        Elasticsearch_v2.es_kibana_rule_update_command({"rule_id": "rule-id-1", "entry_id": "123@abc"}, {})

        call_args = mock_request.call_args
        assert call_args[1]["json_data"] == {"name": "From File"}

    def test_update_rule_missing_rule_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_rule_update_command({}, {})


class TestEsKibanaRuleAlertMuteUnmuteCommands:
    """Tests for es_kibana_rule_alert_mute_command and es_kibana_rule_alert_unmute_command."""

    def test_mute_specific_alert(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_rule_alert_mute_command({"rule_id": "rule-id-1", "alert_id": "alert-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/alert/alert-1/_mute"
        assert "alert-1" in result.readable_output

    def test_mute_all(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        Elasticsearch_v2.es_kibana_rule_alert_mute_command({"rule_id": "rule-id-1", "mute_all": "true"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/_mute_all"

    def test_mute_missing_alert_id_and_mute_all_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_rule_alert_mute_command({"rule_id": "rule-id-1"}, {})

    def test_mute_missing_rule_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_rule_alert_mute_command({"alert_id": "alert-1"}, {})

    def test_unmute_specific_alert(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_rule_alert_unmute_command({"rule_id": "rule-id-1", "alert_id": "alert-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/alert/alert-1/_unmute"
        assert "alert-1" in result.readable_output

    def test_unmute_all(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        Elasticsearch_v2.es_kibana_rule_alert_unmute_command({"rule_id": "rule-id-1", "unmute_all": "true"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/alerting/rule/rule-id-1/_unmute_all"


class TestEsKibanaDetectionAlertStatusSetCommand:
    """Tests for es_kibana_detection_alert_status_set_command."""

    def test_set_status_by_signal_ids(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"total": 2, "updated": 2})
        mocker.patch("Elasticsearch_v2.safe_load_json", return_value=None)

        result = Elasticsearch_v2.es_kibana_detection_alert_status_set_command({"status": "closed", "signal_ids": "id1,id2"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/detection_engine/signals/status"
        assert call_args[1]["json_data"]["signal_ids"] == ["id1", "id2"]
        assert result.outputs == {"total": 2, "updated": 2}

    def test_set_status_by_query(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"total": 1, "updated": 1})

        Elasticsearch_v2.es_kibana_detection_alert_status_set_command({"status": "open", "query": '{"match_all": {}}'}, {})

        call_args = mock_request.call_args
        assert call_args[1]["json_data"]["query"] == {"match_all": {}}

    def test_missing_status_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_detection_alert_status_set_command({}, {})


MOCK_EXCEPTION_ITEM = {
    "id": "item-id-1",
    "item_id": "trusted-linux-processes",
    "list_id": "list-id-1",
    "name": "Test Item",
    "description": "A test item",
    "created_at": "2024-01-01T00:00:00.000Z",
}

MOCK_EXCEPTION_LIST = {
    "id": "list-id-1",
    "list_id": "trusted-linux-processes",
    "name": "Test List",
    "description": "A test list",
    "created_at": "2024-01-01T00:00:00.000Z",
}


class TestBuildExceptionEntry:
    """Tests for build_exception_entry."""

    def test_no_entries_returns_none(self):
        import Elasticsearch_v2

        assert Elasticsearch_v2.build_exception_entry({}) is None

    def test_simple_value_entry(self):
        import Elasticsearch_v2

        entry = Elasticsearch_v2.build_exception_entry(
            {"entries_field": "file.path", "entries_type": "match", "entries_operator": "included", "entries_value": "/bin/bash"}
        )

        assert entry == {"field": "file.path", "type": "match", "operator": "included", "value": "/bin/bash"}

    def test_list_type_entry(self):
        import Elasticsearch_v2

        entry = Elasticsearch_v2.build_exception_entry(
            {
                "entries_field": "file.hash",
                "entries_type": "list",
                "entries_list_id": "list1",
                "entries_list_type": "keyword",
            }
        )

        assert entry["list"] == {"id": "list1", "type": "keyword"}


class TestEsKibanaEndpointExceptionListItemCreateCommand:
    """Tests for es_kibana_endpoint_exception_list_item_create_command."""

    def test_create_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_endpoint_exception_list_item_create_command(
            {"name": "Test Item", "description": "A test item"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/endpoint_list/items"
        assert call_args[1]["json_data"]["type"] == "simple"
        assert result.outputs == MOCK_EXCEPTION_ITEM
        assert result.outputs_prefix == "Elasticsearch.Kibana.EndpointExceptionListItem"

    def test_create_with_entry_id(self, mocker):
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.get_json_body_from_entry_id", return_value={"name": "From File"})
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        Elasticsearch_v2.es_kibana_endpoint_exception_list_item_create_command({"entry_id": "123@abc"}, {})

        call_args = mock_request.call_args
        assert call_args[1]["json_data"] == {"name": "From File"}


class TestEsKibanaEndpointExceptionListItemUpdateCommand:
    """Tests for es_kibana_endpoint_exception_list_item_update_command."""

    def test_update_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_endpoint_exception_list_item_update_command(
            {"exception_list_item_id": "item-id-1", "_version": "v1", "name": "Updated"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[1]["json_data"]["id"] == "item-id-1"
        assert call_args[1]["json_data"]["_version"] == "v1"
        assert result.outputs == MOCK_EXCEPTION_ITEM


class TestEsKibanaEndpointExceptionListItemDeleteCommand:
    """Tests for es_kibana_endpoint_exception_list_item_delete_command."""

    def test_delete_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_endpoint_exception_list_item_delete_command(
            {"item_id": "trusted-linux-processes"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "DELETE"
        assert "trusted-linux-processes" in result.readable_output

    def test_missing_item_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_endpoint_exception_list_item_delete_command({}, {})


class TestEsKibanaEndpointExceptionListItemListCommand:
    """Tests for es_kibana_endpoint_exception_list_item_list_command."""

    def test_list_by_item_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_endpoint_exception_list_item_list_command({"item_id": "trusted-linux-processes"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/endpoint_list/items"
        assert result.outputs == [MOCK_EXCEPTION_ITEM]

    def test_list_find(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_EXCEPTION_ITEM]})

        result = Elasticsearch_v2.es_kibana_endpoint_exception_list_item_list_command({"page": "1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/endpoint_list/items/_find"
        assert result.outputs == [MOCK_EXCEPTION_ITEM]


class TestEsKibanaExceptionListListCommand:
    """Tests for es_kibana_exception_list_list_command."""

    def test_list_by_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_LIST)

        result = Elasticsearch_v2.es_kibana_exception_list_list_command({"exception_list_id": "list-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/exception_lists"
        assert result.outputs == [MOCK_EXCEPTION_LIST]

    def test_list_find(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_EXCEPTION_LIST]})

        result = Elasticsearch_v2.es_kibana_exception_list_list_command({}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/exception_lists/_find"
        assert result.outputs == [MOCK_EXCEPTION_LIST]


class TestEsKibanaExceptionListCreateCommand:
    """Tests for es_kibana_exception_list_create_command."""

    def test_create_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_LIST)

        result = Elasticsearch_v2.es_kibana_exception_list_create_command({"name": "Test List", "type": "detection"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[1]["json_data"]["type"] == "detection"
        assert result.outputs == MOCK_EXCEPTION_LIST

    def test_missing_type_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_exception_list_create_command({"name": "Test List"}, {})


class TestEsKibanaExceptionListUpdateCommand:
    """Tests for es_kibana_exception_list_update_command."""

    def test_update_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_LIST)

        result = Elasticsearch_v2.es_kibana_exception_list_update_command(
            {"description": "desc", "name": "Test List", "type": "detection", "exception_list_id": "list-id-1"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[1]["json_data"]["id"] == "list-id-1"
        assert result.outputs == MOCK_EXCEPTION_LIST

    def test_missing_required_field_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_exception_list_update_command({"name": "Test List", "type": "detection"}, {})


class TestEsKibanaExceptionListDeleteCommand:
    """Tests for es_kibana_exception_list_delete_command."""

    def test_delete_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_exception_list_delete_command({"exception_list_id": "list-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "DELETE"
        assert "list-id-1" in result.readable_output

    def test_missing_identifiers_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_exception_list_delete_command({}, {})


class TestEsKibanaExceptionListItemListCommand:
    """Tests for es_kibana_exception_list_item_list_command."""

    def test_list_by_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_exception_list_item_list_command({"exception_list_item_id": "item-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/exception_lists/items"
        assert result.outputs == [MOCK_EXCEPTION_ITEM]

    def test_list_find(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_EXCEPTION_ITEM]})

        result = Elasticsearch_v2.es_kibana_exception_list_item_list_command({"search": "test"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/exception_lists/items/_find"
        assert result.outputs == [MOCK_EXCEPTION_ITEM]


class TestEsKibanaExceptionListItemCreateCommand:
    """Tests for es_kibana_exception_list_item_create_command."""

    def test_create_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_exception_list_item_create_command({"name": "Test Item", "list_id": "list-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/exception_lists/items"
        assert result.outputs == MOCK_EXCEPTION_ITEM


class TestEsKibanaExceptionItemListUpdateCommand:
    """Tests for es_kibana_exception_item_list_update_command."""

    def test_update_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_EXCEPTION_ITEM)

        result = Elasticsearch_v2.es_kibana_exception_item_list_update_command(
            {"exception_list_item_id": "item-id-1", "name": "Updated"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[1]["json_data"]["id"] == "item-id-1"
        assert result.outputs == MOCK_EXCEPTION_ITEM


class TestEsKibanaExceptionListItemDeleteCommand:
    """Tests for es_kibana_exception_list_item_delete_command."""

    def test_delete_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_exception_list_item_delete_command({"exception_list_item_id": "item-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "DELETE"
        assert "item-id-1" in result.readable_output

    def test_missing_identifiers_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_exception_list_item_delete_command({}, {})


MOCK_VALUE_LIST = {
    "id": "value-list-id-1",
    "name": "Test Value List",
    "description": "A test value list",
    "created_at": "2024-01-01T00:00:00.000Z",
}

MOCK_VALUE_LIST_ITEM = {
    "id": "value-list-item-id-1",
    "list_id": "value-list-id-1",
    "name": "Test Item",
    "description": "A test value list item",
    "created_at": "2024-01-01T00:00:00.000Z",
}


class TestEsKibanaValueListsListCommand:
    """Tests for es_kibana_value_lists_list_command."""

    def test_list_by_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_VALUE_LIST)

        result = Elasticsearch_v2.es_kibana_value_lists_list_command({"value_list_id": "value-list-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/lists"
        assert result.outputs == [MOCK_VALUE_LIST]

    def test_list_find(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_VALUE_LIST]})

        result = Elasticsearch_v2.es_kibana_value_lists_list_command({}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/lists/_find"
        assert result.outputs == [MOCK_VALUE_LIST]


class TestEsKibanaValueListItemGetCommand:
    """Tests for es_kibana_value_list_item_get_command."""

    def test_get_by_item_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_VALUE_LIST_ITEM)

        result = Elasticsearch_v2.es_kibana_value_list_item_get_command({"value_list_item_id": "item-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/lists/items"
        assert result.outputs == [MOCK_VALUE_LIST_ITEM]

    def test_get_by_value_only(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_VALUE_LIST_ITEM)

        Elasticsearch_v2.es_kibana_value_list_item_get_command({"value": "1.2.3.4"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/lists/items"
        assert call_args[1]["params"]["value"] == "1.2.3.4"

    def test_get_find(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={"data": [MOCK_VALUE_LIST_ITEM]})

        result = Elasticsearch_v2.es_kibana_value_list_item_get_command({"value_list_id": "value-list-id-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][1] == "/api/lists/items/_find"
        assert result.outputs == [MOCK_VALUE_LIST_ITEM]


class TestEsKibanaValueListItemCreateCommand:
    """Tests for es_kibana_value_list_item_create_command."""

    def test_create_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_VALUE_LIST_ITEM)

        result = Elasticsearch_v2.es_kibana_value_list_item_create_command(
            {"value_list_id": "value-list-id-1", "value": "1.2.3.4"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[1]["json_data"] == {"list_id": "value-list-id-1", "value": "1.2.3.4"}
        assert result.outputs == MOCK_VALUE_LIST_ITEM

    def test_missing_value_list_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_value_list_item_create_command({"value": "1.2.3.4"}, {})

    def test_missing_value_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_value_list_item_create_command({"value_list_id": "value-list-id-1"}, {})


class TestEsKibanaValueListItemUpdateCommand:
    """Tests for es_kibana_value_list_item_update_command."""

    def test_update_success(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=MOCK_VALUE_LIST_ITEM)

        result = Elasticsearch_v2.es_kibana_value_list_item_update_command(
            {"value_list_item_id": "item-1", "value": "5.6.7.8"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "PUT"
        assert call_args[1]["json_data"]["id"] == "item-1"
        assert result.outputs == MOCK_VALUE_LIST_ITEM

    def test_missing_value_list_item_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_value_list_item_update_command({"value": "1.2.3.4"}, {})


class TestEsKibanaValueListItemDeleteCommand:
    """Tests for es_kibana_value_list_item_delete_command."""

    def test_delete_by_item_id(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        result = Elasticsearch_v2.es_kibana_value_list_item_delete_command({"value_list_item_id": "item-1"}, {})

        call_args = mock_request.call_args
        assert call_args[0][0] == "DELETE"
        assert "item-1" in result.readable_output

    def test_delete_by_list_id_and_value(self, mocker):
        import Elasticsearch_v2

        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value={})

        Elasticsearch_v2.es_kibana_value_list_item_delete_command({"value_list_id": "value-list-id-1", "value": "1.2.3.4"}, {})

        call_args = mock_request.call_args
        assert call_args[1]["params"]["list_id"] == "value-list-id-1"
        assert call_args[1]["params"]["value"] == "1.2.3.4"

    def test_missing_identifiers_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_value_list_item_delete_command({}, {})


class TestEsKibanaValueListItemExportCommand:
    """Tests for es_kibana_value_list_item_export_command."""

    def test_export_success(self, mocker):
        import Elasticsearch_v2

        mocker.patch("Elasticsearch_v2.kibana_http_request", return_value="1.2.3.4\n5.6.7.8")
        mocker.patch("Elasticsearch_v2.fileResult", return_value={"Type": 3, "File": "value-list-items.txt"})

        results = Elasticsearch_v2.es_kibana_value_list_item_export_command({"value_list_id": "value-list-id-1"}, {})

        assert isinstance(results, list)
        assert len(results) == 2
        assert results[0].readable_output == "Successful response"


class TestEsKibanaValueListItemImportCommand:
    """Tests for es_kibana_value_list_item_import_command."""

    def test_import_success(self, mocker, tmp_path):
        import Elasticsearch_v2

        file_path = tmp_path / "values.txt"
        file_path.write_text("1.2.3.4\n5.6.7.8")
        mocker.patch("Elasticsearch_v2.demisto.getFilePath", return_value={"path": str(file_path), "name": "values.txt"})
        mock_request = mocker.patch("Elasticsearch_v2.kibana_http_request", return_value=[MOCK_VALUE_LIST_ITEM])

        result = Elasticsearch_v2.es_kibana_value_list_item_import_command(
            {"entry_id": "123@abc", "value_list_id": "value-list-id-1", "type": "ip"}, {}
        )

        call_args = mock_request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/api/lists/items/_import"
        assert "files" in call_args[1]
        assert result.outputs == [MOCK_VALUE_LIST_ITEM]

    def test_missing_entry_id_raises(self):
        import Elasticsearch_v2
        from CommonServerPython import DemistoException

        with pytest.raises(DemistoException):
            Elasticsearch_v2.es_kibana_value_list_item_import_command({}, {})

from datetime import datetime
from unittest.mock import patch
import demistomock as demisto
import importlib
import Elasticsearch_v2
import pytest
import requests
import unittest
from unittest import mock
import dateparser

"""MOCKED RESPONSES"""

ES_V6_RESPONSE = {
    'took': 1,
    'timed_out': False,
    '_shards': {
        'total': 5,
        'successful': 5,
        'skipped': 0,
        'failed': 0
    },
    'hits': {
        'total': 17,
        'max_score': 1.3862944,
        'hits': [
            {
                '_index': 'users',
                '_type': '_doc',
                '_id': '123',
                '_score': 1.3862944,
                '_source': {
                    'Date': '2019-08-29T14:45:00.123Z'
                }
            }, {
                '_index': 'users',
                '_type': '_doc',
                '_id': '456',
                '_score': 0.9517491,
                '_source': {
                    'Date': '2019-08-29T14:46:00.123456Z'
                }
            }
        ]
    }
}

ES_V7_RESPONSE = {
    'took': 1,
    'timed_out': False,
    '_shards': {
        'total': 1,
        'successful': 1,
        'skipped': 0,
        'failed': 0
    },
    'hits': {
        'total': {
            'value': 9,
            'relation': 'eq'
        },
        'max_score': 0.6814878,
        'hits': [
            {
                '_index': 'customer',
                '_type': 'doc',
                '_id': '123',
                '_score': 0.6814878,
                '_source': {
                    'Date': '2019-08-27T18:00:00Z'
                }
            }, {
                '_index': 'customer',
                '_type': 'doc',
                '_id': '456',
                '_score': 0.6814878,
                '_source': {
                    'Date': '2019-08-27T18:01:25.343212Z'
                }
            }
        ]
    }
}

MOCK_ES7_SEARCH_CONTEXT = str({
    'Server': '',
    'Index': 'customer',
    'Query': 'check',
    'Page': 0,
    'Size': 2,
    'total': {
        'value': 9,
        'relation': 'eq'
    },
    'max_score': 0.6814878,
    'took': 1,
    'timed_out': False,
    'Results': [
        {
            '_index': 'customer',
            '_type': 'doc',
            '_id': '123',
            '_score': 0.6814878,
            '_source': {'Date': '2019-08-27T18:00:00Z'}
        },
        {
            '_index': 'customer',
            '_type': 'doc',
            '_id': '456',
            '_score': 0.6814878,
            '_source': {'Date': '2019-08-27T18:01:25.343212Z'}
        }
    ]
})

MOCK_ES7_HIT_CONTEXT = str([
    {
        '_index': 'customer',
        '_id': '123',
        '_type': 'doc',
        '_score': 0.6814878,
        'Date': '2019-08-27T18:00:00Z'
    },
    {
        '_index': 'customer',
        '_id': '456',
        '_type': 'doc',
        '_score': 0.6814878,
        'Date': '2019-08-27T18:01:25.343212Z'
    }
])

MOCK_ES6_SEARCH_CONTEXT = str({
    'Server': '',
    'Index': 'users',
    'Query': 'incident',
    'Page': 0,
    'Size': 2,
    'total': {
        'value': 17
    },
    'max_score': 1.3862944,
    'took': 1,
    'timed_out': False,
    'Results': [
        {
            '_index': 'users',
            '_type': '_doc',
            '_id': '123',
            '_score': 1.3862944,
            '_source': {'Date': '2019-08-29T14:45:00.123Z'}
        },
        {
            '_index': 'users',
            '_type': '_doc',
            '_id': '456',
            '_score': 0.9517491,
            '_source': {'Date': '2019-08-29T14:46:00.123456Z'}
        }
    ]
})

MOCK_ES6_HIT_CONTEXT = str([
    {
        '_index': 'users',
        '_id': '123',
        '_type': '_doc',
        '_score': 1.3862944,
        'Date': '2019-08-29T14:45:00.123Z'
    },
    {
        '_index': 'users',
        '_id': '456',
        '_type': '_doc',
        '_score': 0.9517491,
        'Date': '2019-08-29T14:46:00.123456Z'
    }
])

MOCK_ES7_INCIDENTS = str([
    {
        'name': 'Elasticsearch: Index: customer, ID: 123',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "123", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "2019-08-27T18:00:00Z"}'
                   '}',
        'occurred': '2019-08-27T18:00:00Z',
        'dbotMirrorId': '123',
        'labels': [
            {
                'type': 'Date',
                'value': '2019-08-27T18:00:00Z'
            }
        ]
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "2019-08-27T18:01:25.343212Z"}'
                   '}',
        'occurred': '2019-08-27T18:01:25Z',
        'dbotMirrorId': '456',
        'labels': [
            {
                'type': 'Date',
                'value': '2019-08-27T18:01:25.343212Z'
            }
        ]
    }
])

MOCK_ES7_INCIDENTS_WITHOUT_LABELS = str([
    {
        'name': 'Elasticsearch: Index: customer, ID: 123',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "123", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "2019-08-27T18:00:00Z"}'
                   '}',
        'occurred': '2019-08-27T18:00:00Z',
        'dbotMirrorId': '123'
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "2019-08-27T18:01:25.343212Z"}'
                   '}',
        'occurred': '2019-08-27T18:01:25Z',
        'dbotMirrorId': '456'
    }
])

MOCK_ES6_INCIDETNS = str([
    {
        'name': 'Elasticsearch: Index: users, ID: 123',
        'rawJSON': '{'
                   '"_index": "users", '
                   '"_type": "_doc", '
                   '"_id": "123", '
                   '"_score": 1.3862944, '
                   '"_source": {"Date": "2019-08-29T14:45:00.123Z"}'
                   '}',
        'occurred': '2019-08-29T14:45:00Z',
        'dbotMirrorId': '123',
        'labels':
            [
                {
                    'type': 'Date',
                    'value': '2019-08-29T14:45:00.123Z'
                }
            ]
    }, {
        'name': 'Elasticsearch: Index: users, ID: 456',
        'rawJSON': '{'
                   '"_index": "users", '
                   '"_type": "_doc", '
                   '"_id": "456", '
                   '"_score": 0.9517491, '
                   '"_source": {"Date": "2019-08-29T14:46:00.123456Z"}'
                   '}',
        'occurred': '2019-08-29T14:46:00Z',
        'dbotMirrorId': '456',
        'labels':
            [
                {
                    'type': 'Date',
                    'value': '2019-08-29T14:46:00.123456Z'
                }
            ]
    }
])

MOCK_ES6_INCIDETNS_WITHOUT_LABELS = str([
    {
        'name': 'Elasticsearch: Index: users, ID: 123',
        'rawJSON': '{'
                   '"_index": "users", '
                   '"_type": "_doc", '
                   '"_id": "123", '
                   '"_score": 1.3862944, '
                   '"_source": {"Date": "2019-08-29T14:45:00.123Z"}'
                   '}',
        'occurred': '2019-08-29T14:45:00Z',
        'dbotMirrorId': '123'
    }, {
        'name': 'Elasticsearch: Index: users, ID: 456',
        'rawJSON': '{'
                   '"_index": "users", '
                   '"_type": "_doc", '
                   '"_id": "456", '
                   '"_score": 0.9517491, '
                   '"_source": {"Date": "2019-08-29T14:46:00.123456Z"}'
                   '}',
        'occurred': '2019-08-29T14:46:00Z',
        'dbotMirrorId': '456'
    }
])

ES_V7_RESPONSE_WITH_TIMESTAMP = {
    'took': 1,
    'timed_out': False,
    '_shards': {
        'total': 1,
        'successful': 1,
        'skipped': 0,
        'failed': 0
    },
    'hits': {
        'total': {
            'value': 9,
            'relation': 'eq'
        },
        'max_score': 0.6814878,
        'hits': [
            {
                '_index': 'customer',
                '_type': 'doc',
                '_id': '123',
                '_score': 0.6814878,
                '_source': {
                    'Date': '1572502634'
                }
            }, {
                '_index': 'customer',
                '_type': 'doc',
                '_id': '456',
                '_score': 0.6814878,
                '_source': {
                    'Date': '1572502640'
                }
            }
        ]
    }
}

MOCK_ES7_INCIDENTS_FROM_TIMESTAMP = str([
    {
        'name': 'Elasticsearch: Index: customer, ID: 123',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "123", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "1572502634"}'
                   '}',
        'occurred': '2019-10-31T06:17:14Z',
        'dbotMirrorId': '123',
        'labels': [
            {
                'type': 'Date',
                'value': '1572502634'
            }
        ]
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "1572502640"}'
                   '}',
        'occurred': '2019-10-31T06:17:20Z',
        'dbotMirrorId': '456',
        'labels': [
            {
                'type': 'Date',
                'value': '1572502640'
            }
        ]
    }
])

MOCK_ES7_INCIDENTS_FROM_TIMESTAMP_WITHOUT_LABELS = str([
    {
        'name': 'Elasticsearch: Index: customer, ID: 123',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "123", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "1572502634"}'
                   '}',
        'occurred': '2019-10-31T06:17:14Z',
        'dbotMirrorId': '123'
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "1572502640"}'
                   '}',
        'occurred': '2019-10-31T06:17:20Z',
        'dbotMirrorId': '456'
    }
])

MOCK_ES7_SCHEMA_INPUT = {
    "bytes": {
        "type": "long"
    },
    "clientip": {
        "type": "ip"
    }
}

MOCK_ES7_SCHEMA_OUTPUT = {
    "bytes": "type: long",
    "clientip": "type: ip"
}

MOC_ES7_SERVER_RESPONSE = {
    "kibana_sample_data_logs": {
        "mappings": {
            "properties": {
                "@timestamp": {
                    "type": "alias",
                    "path": "timestamp"
                },
                "agent": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "bytes": {
                    "type": "long"
                },
                "clientip": {
                    "type": "ip"
                },
                "event": {
                    "properties": {
                        "dataset": {
                            "type": "keyword"
                        }
                    }
                },
                "extension": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "geo": {
                    "properties": {
                        "coordinates": {
                            "type": "geo_point"
                        },
                        "dest": {
                            "type": "keyword"
                        },
                        "src": {
                            "type": "keyword"
                        },
                        "srcdest": {
                            "type": "keyword"
                        }
                    }
                },
                "host": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "index": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "ip": {
                    "type": "ip"
                },
                "machine": {
                    "properties": {
                        "os": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        },
                        "ram": {
                            "type": "long"
                        }
                    }
                },
                "memory": {
                    "type": "double"
                },
                "message": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "phpmemory": {
                    "type": "long"
                },
                "referer": {
                    "type": "keyword"
                },
                "request": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "response": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "tags": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "timestamp": {
                    "type": "date"
                },
                "url": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 256
                        }
                    }
                },
                "utc_time": {
                    "type": "date"
                }
            }
        }
    }
}

MOCK_PARAMS = [
    {
        'client_type': 'Elasticsearch',
        'fetch_index': 'customer',
        'fetch_time_field': 'Date',
        'time_method': 'Simple-Date',
        'map_labels': True,
        'credentials': {
            'identifier': 'mock',
            'password': 'demisto',
        }
    },
    {
        'client_type': 'Elasticsearch',
        'fetch_index': 'customer',
        'fetch_time_field': 'Date',
        'time_method': 'Simple-Date',
        'map_labels': False,
        'credentials': {
            'identifier': 'mock',
            'password': 'demisto',
        }
    },
    {
        'client_type': 'OpenSearch',
        'fetch_index': 'customer',
        'fetch_time_field': 'Date',
        'time_method': 'Simple-Date',
        'map_labels': True,
        'credentials': {
            'identifier': 'mock',
            'password': 'demisto',
        }
    }
]


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_context_creation_es7(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_context, get_total_results

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V7_RESPONSE)
    query = 'check'
    index = 'customer'
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, base_page,
                                                                               size, total_dict, ES_V7_RESPONSE)

    assert str(search_context) == MOCK_ES7_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', 'max_score', " \
                                "'Server', 'Page', 'Size', 'aggregations']"
    assert str(hit_tables) == MOCK_ES7_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_context_creation_es6(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_context, get_total_results

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V6_RESPONSE)
    query = 'incident'
    index = 'users'
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, base_page,
                                                                               size, total_dict, ES_V6_RESPONSE)

    assert str(search_context) == MOCK_ES6_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', " \
                                "'max_score', 'Server', 'Page', 'Size', 'aggregations']"
    assert str(hit_tables) == MOCK_ES6_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_incident_creation_e6(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = '2019-08-29T14:44:00Z'
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V6_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == '2019-08-29T14:46:00.123456+00:00'
    if params.get('map_labels'):
        assert str(incidents) == MOCK_ES6_INCIDETNS
    else:
        assert str(incidents) == MOCK_ES6_INCIDETNS_WITHOUT_LABELS


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_incident_creation_e7(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = '2019-08-27T17:59:00'
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V7_RESPONSE, last_fetch)

    # last fetch should not truncate the milliseconds
    assert str(last_fetch2) == '2019-08-27T18:01:25.343212+00:00'
    if params.get('map_labels'):
        assert str(incidents) == MOCK_ES7_INCIDENTS
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_WITHOUT_LABELS


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_timestamp_to_date_converter_seconds(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch('Elasticsearch_v2.TIME_METHOD', 'Timestamp-Seconds')
    from Elasticsearch_v2 import timestamp_to_date
    seconds_since_epoch = "1572164838"
    assert str(timestamp_to_date(seconds_since_epoch)) == "2019-10-27 08:27:18"


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_timestamp_to_date_converter_milliseconds(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch('Elasticsearch_v2.TIME_METHOD', 'Timestamp-Milliseconds')
    from Elasticsearch_v2 import timestamp_to_date
    milliseconds_since_epoch = "1572164838123"
    assert str(timestamp_to_date(milliseconds_since_epoch)) == "2019-10-27 08:27:18.123000"


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_incident_creation_with_timestamp_e7(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch('Elasticsearch_v2.TIME_METHOD', 'Timestamp-Seconds')
    from Elasticsearch_v2 import results_to_incidents_timestamp
    lastfetch = int(datetime.strptime('2019-08-27T17:59:00Z', '%Y-%m-%dT%H:%M:%SZ').timestamp())
    incidents, last_fetch2 = results_to_incidents_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, lastfetch)
    assert last_fetch2 == 1572502640
    if params.get('map_labels'):
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP
    else:
        assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP_WITHOUT_LABELS


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_format_to_iso(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
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


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_elasticsearch_builder_called_with_username_password(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import Elasticsearch, elasticsearch_builder
    es_mock = mocker.patch.object(Elasticsearch, '__init__', return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get('http_auth') == ('mock', 'demisto')
    assert es_mock.call_args[1].get('api_key') is None


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_elasticsearch_builder_called_with_no_creds(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    mocker.patch('Elasticsearch_v2.USERNAME', None)
    mocker.patch('Elasticsearch_v2.PASSWORD', None)
    from Elasticsearch_v2 import Elasticsearch, elasticsearch_builder
    es_mock = mocker.patch.object(Elasticsearch, '__init__', return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get('http_auth') is None
    assert es_mock.call_args[1].get('api_key') is None


@pytest.mark.parametrize('params', MOCK_PARAMS)
def test_elasticsearch_parse_subtree(params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    importlib.reload(Elasticsearch_v2)  # To reset the Elasticsearch client with the OpenSearch library
    from Elasticsearch_v2 import parse_subtree
    sub_tree = parse_subtree(MOCK_ES7_SCHEMA_INPUT)
    assert str(sub_tree) == str(MOCK_ES7_SCHEMA_OUTPUT)


# This is the class we want to test
'''
The get-mapping-fields command perform a GET /<index name>/_mapping http command
for e.g http://elasticserver.com/customers/_mapping the output is then formatted and arranged by the parse-tree function
The test created a mock response.
'''


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

    if args[0] == 'http://someurl.com/' + 'index' + '/_mapping':
        return MockResponse(MOC_ES7_SERVER_RESPONSE, 200)
    else:
        return MockResponse(None, 404)


# Our test case class
class GetMappingFields(unittest.TestCase):

    # We patch 'requests.get' with our own method. The mock object is passed in to our test case method.
    @mock.patch('requests.get', side_effect=mocked_requests_get)
    def test_fetch(self, mock_get):
        # Assert requests.get calls
        gmf = GetMapping()
        server_response = gmf.fetch_json('http://someurl.com/' + 'index' + '/_mapping')
        assert server_response == MOC_ES7_SERVER_RESPONSE


class TestIncidentLabelMaker(unittest.TestCase):
    def test_sanity(self):
        from Elasticsearch_v2 import incident_label_maker

        sources = {
            'first_name': 'John',
            'sur_name': 'Snow',
        }
        expected_labels = [
            {
                'type': 'first_name',
                'value': 'John'
            },
            {
                'type': 'sur_name',
                'value': 'Snow'
            },
        ]

        labels = incident_label_maker(sources)
        assert labels == expected_labels

    def test_complex_value(self):
        from Elasticsearch_v2 import incident_label_maker

        sources = {
            'name': 'Ash',
            'action': 'catch',
            'targets': ['Pikachu', 'Charmander', 'Squirtle', 'Bulbasaur'],
        }
        expected_labels = [
            {
                'type': 'name',
                'value': 'Ash',
            },
            {
                'type': 'action',
                'value': 'catch',
            },
            {
                'type': 'targets',
                'value': '["Pikachu", "Charmander", "Squirtle", "Bulbasaur"]',
            },
        ]

        labels = incident_label_maker(sources)
        assert labels == expected_labels


@pytest.mark.parametrize('time_method, last_fetch, time_range_start, time_range_end, result',
                         [('Timestamp-Milliseconds', '', '1.1.2000 12:00:00Z', '2.1.2000 12:00:00Z',
                           {'range': {'time_field': {'gt': 946728000000, 'lt': 949406400000}}}),
                          ('Timestamp-Milliseconds', 946728000000, '', '2.1.2000 12:00:00Z',
                           {'range': {'time_field': {'gt': 946728000000, 'lt': 949406400000}}}),
                          ('Timestamp-Milliseconds', '', '', '2.1.2000 12:00:00Z',
                           {'range': {'time_field': {'lt': 949406400000}}}),
                          ('Simple-Date', '2.1.2000 12:00:00.000000', '', '',
                           {'range': {'time_field': {'gt': '2.1.2000 12:00:00.000000',
                                                     'format': Elasticsearch_v2.ES_DEFAULT_DATETIME_FORMAT}}}),
                          ])
def test_get_time_range(time_method, last_fetch, time_range_start, time_range_end, result):
    Elasticsearch_v2.TIME_METHOD = time_method
    from Elasticsearch_v2 import get_time_range
    assert get_time_range(last_fetch, time_range_start, time_range_end, "time_field") == result


def test_build_eql_body():
    from Elasticsearch_v2 import build_eql_body
    assert build_eql_body(None, None, None, None, None, None, None) == {}
    assert build_eql_body("query", "fields", "size", "tiebreaker_field",
                          "timestamp_field", "event_category_field", "filter") == {
        "query": "query",
        "fields": "fields",
        "size": "size",
        "tiebreaker_field": "tiebreaker_field",
        "timestamp_field": "timestamp_field",
        "event_category_field": "event_category_field",
        "filter": "filter"
    }


first_case_all_with_empty_string = ('', {'a': {'mappings': {'properties': {'example': {}}}}},
                                    {'a': {'_id': 'doc_id', '_index': 'a', '_source': {'example': 'type: '}}}
                                    )
second_case_with_prefix_and_wildcard = ('.internal.alerts-*',
                                        {'.internal.alerts-security': {'mappings': {'properties': {'example': {}}}},
                                         '.internal': {'mappings': {'properties': {'example': {}}}}},
                                        {'.internal.alerts-security':
                                            {'_id': 'doc_id', '_index': '.internal.alerts-security',
                                                '_source': {'example': 'type: '}}}
                                        )
third_regular_case = ('a', {'a': {'mappings': {'properties': {'example': {}}}}},
                      {'a': {'_id': 'doc_id', '_index': 'a', '_source': {'example': 'type: '}}})


@pytest.mark.parametrize('indexes, response, expected_result',
                         [first_case_all_with_empty_string, second_case_with_prefix_and_wildcard, third_regular_case])
def test_get_mapping_fields_command(mocker, indexes, response, expected_result):
    class ResponseMockObject:
        def json(self):
            return response

    mocker.patch('Elasticsearch_v2.FETCH_INDEX', indexes)
    mocker.patch('Elasticsearch_v2.requests.get', return_value=ResponseMockObject())
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
     - make sure that the size / page arguments are getting called when using query_dsl
    """
    import Elasticsearch_v2
    Elasticsearch_v2.FETCH_INDEX = 'index from parameter'
    index_from_arg = 'index from arg'
    mocker.patch.object(
        demisto, 'args', return_value={'index': index_from_arg, 'query_dsl': 'test', 'size': '5', 'page': '0'}
    )
    search_mock = mocker.patch.object(Elasticsearch_v2.Elasticsearch, 'search', return_value=ES_V7_RESPONSE)
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, '__init__', return_value=None)
    Elasticsearch_v2.search_command({})
    assert search_mock.call_args.kwargs['index'] == index_from_arg
    assert search_mock.call_args.kwargs['size'] == 5
    assert search_mock.call_args.kwargs['from_'] == 0


def test_execute_raw_query(mocker):
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
    Elasticsearch_v2.FETCH_INDEX = 'index from parameter'
    mocker.patch.object(
        Elasticsearch_v2.Elasticsearch, 'search', return_value=ES_V7_RESPONSE
    )
    mocker.patch.object(Elasticsearch_v2.Elasticsearch, '__init__', return_value=None)
    es = Elasticsearch_v2.elasticsearch_builder({})
    assert Elasticsearch_v2.execute_raw_query(es, 'dsadf') == ES_V7_RESPONSE


@pytest.mark.parametrize('date_time, time_method, expected_time', [
    ('123456', 'Timestamp-Seconds', 123456),
    ('123456', 'Timestamp-Milliseconds', 123456),
    (dateparser.parse('July 1, 2023'), 'Simple-Date', '2023-07-01 00:00:00.000000'),
    (dateparser.parse('2023-07-01 23:24:25.123456'), 'Simple-Date', '2023-07-01 23:24:25.123456'),
])
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

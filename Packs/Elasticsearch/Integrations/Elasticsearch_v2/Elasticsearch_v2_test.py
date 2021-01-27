from datetime import datetime
from unittest.mock import patch
from dateutil.parser import parse
import requests
import unittest
from unittest import mock

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
                    'Date': '2019-08-29T14:45:00Z'
                }
            }, {
                '_index': 'users',
                '_type': '_doc',
                '_id': '456',
                '_score': 0.9517491,
                '_source': {
                    'Date': '2019-08-29T14:46:00Z'
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
                    'Date': '2019-08-27T18:01:00Z'
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
            '_source': {'Date': '2019-08-27T18:01:00Z'}
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
        'Date': '2019-08-27T18:01:00Z'
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
            '_source': {'Date': '2019-08-29T14:45:00Z'}
        },
        {
            '_index': 'users',
            '_type': '_doc',
            '_id': '456',
            '_score': 0.9517491,
            '_source': {'Date': '2019-08-29T14:46:00Z'}
        }
    ]
})

MOCK_ES6_HIT_CONTEXT = str([
    {
        '_index': 'users',
        '_id': '123',
        '_type': '_doc',
        '_score': 1.3862944,
        'Date': '2019-08-29T14:45:00Z'
    },
    {
        '_index': 'users',
        '_id': '456',
        '_type': '_doc',
        '_score': 0.9517491,
        'Date': '2019-08-29T14:46:00Z'
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
        'labels': [
            {
                'type': 'Date',
                'value': '2019-08-27T18:00:00Z'
            }
        ],
        'occurred': '2019-08-27T18:00:00Z'
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "2019-08-27T18:01:00Z"}'
                   '}',
        'labels': [
            {
                'type': 'Date',
                'value': '2019-08-27T18:01:00Z'
            }
        ],
        'occurred': '2019-08-27T18:01:00Z'
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
                   '"_source": {"Date": "2019-08-29T14:45:00Z"}'
                   '}',
        'labels':
            [
                {
                    'type': 'Date',
                    'value': '2019-08-29T14:45:00Z'
                }
            ],
        'occurred': '2019-08-29T14:45:00Z'
    }, {
        'name': 'Elasticsearch: Index: users, ID: 456',
        'rawJSON': '{'
                   '"_index": "users", '
                   '"_type": "_doc", '
                   '"_id": "456", '
                   '"_score": 0.9517491, '
                   '"_source": {"Date": "2019-08-29T14:46:00Z"}'
                   '}',
        'labels':
            [
                {
                    'type': 'Date',
                    'value': '2019-08-29T14:46:00Z'
                }
            ],
        'occurred': '2019-08-29T14:46:00Z'
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
        'labels': [
            {
                'type': 'Date',
                'value': '1572502634'
            }
        ],
        'occurred': '2019-10-31T06:17:14Z'
    }, {
        'name': 'Elasticsearch: Index: customer, ID: 456',
        'rawJSON': '{'
                   '"_index": "customer", '
                   '"_type": "doc", '
                   '"_id": "456", '
                   '"_score": 0.6814878, '
                   '"_source": {"Date": "1572502640"}'
                   '}',
        'labels': [
            {
                'type': 'Date',
                'value': '1572502640'
            }
        ],
        'occurred': '2019-10-31T06:17:20Z'
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


def test_context_creation_es7():
    from Elasticsearch_v2 import results_to_context, get_total_results

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V7_RESPONSE)
    query = 'check'
    index = 'customer'
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, base_page,
                                                                               size, total_dict, ES_V7_RESPONSE)

    assert str(search_context) == MOCK_ES7_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size']"
    assert str(hit_tables) == MOCK_ES7_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


def test_context_creation_es6():
    from Elasticsearch_v2 import results_to_context, get_total_results

    base_page = 0
    size = 2
    total_dict, total_results = get_total_results(ES_V6_RESPONSE)
    query = 'incident'
    index = 'users'
    search_context, meta_headers, hit_tables, hit_headers = results_to_context(index, query, base_page,
                                                                               size, total_dict, ES_V6_RESPONSE)

    assert str(search_context) == MOCK_ES6_SEARCH_CONTEXT
    assert str(meta_headers) == "['Query', 'took', 'timed_out', 'total', 'max_score', 'Server', 'Page', 'Size']"
    assert str(hit_tables) == MOCK_ES6_HIT_CONTEXT
    assert str(hit_headers) == "['_id', '_index', '_type', '_score', 'Date']"


@patch("Elasticsearch_v2.TIME_METHOD", 'Simple-Date')
@patch("Elasticsearch_v2.TIME_FIELD", 'Date')
@patch("Elasticsearch_v2.FETCH_INDEX", "users")
def test_incident_creation_e6():
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = parse('2019-08-29T14:44:00Z')
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V6_RESPONSE, last_fetch)

    assert str(last_fetch2) == '2019-08-29T14:46:00Z'
    assert str(incidents) == MOCK_ES6_INCIDETNS


@patch("Elasticsearch_v2.TIME_METHOD", 'Simple-Date')
@patch("Elasticsearch_v2.TIME_FIELD", 'Date')
@patch("Elasticsearch_v2.FETCH_INDEX", "customer")
def test_incident_creation_e7():
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = parse('2019-08-27T17:59:00')
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V7_RESPONSE, last_fetch)

    assert str(last_fetch2) == '2019-08-27T18:01:00Z'
    assert str(incidents) == MOCK_ES7_INCIDENTS


@patch("Elasticsearch_v2.TIME_METHOD", 'Timestamp-Seconds')
def test_timestamp_to_date_converter_seconds():
    from Elasticsearch_v2 import timestamp_to_date
    seconds_since_epoch = "1572164838"
    assert str(timestamp_to_date(seconds_since_epoch)) == "2019-10-27 08:27:18"


@patch("Elasticsearch_v2.TIME_METHOD", 'Timestamp-Milliseconds')
def test_timestamp_to_date_converter_milliseconds():
    from Elasticsearch_v2 import timestamp_to_date
    milliseconds_since_epoch = "1572164838123"
    assert str(timestamp_to_date(milliseconds_since_epoch)) == "2019-10-27 08:27:18.123000"


@patch("Elasticsearch_v2.TIME_METHOD", 'Timestamp-Seconds')
@patch("Elasticsearch_v2.TIME_FIELD", 'Date')
@patch("Elasticsearch_v2.FETCH_INDEX", "customer")
def test_incident_creation_with_timestamp_e7():
    from Elasticsearch_v2 import results_to_incidents_timestamp
    lastfetch = int(datetime.strptime('2019-08-27T17:59:00Z', '%Y-%m-%dT%H:%M:%SZ').timestamp())
    incidents, last_fetch2 = results_to_incidents_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, lastfetch)
    assert last_fetch2 == 1572502640
    assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP


def test_format_to_iso():
    from Elasticsearch_v2 import format_to_iso
    date_string_1 = "2020-02-03T10:00:00"
    date_string_2 = "2020-02-03T10:00:00+02:00"
    date_string_3 = "2020-02-03T10:00:00-02:00"
    iso_format = "2020-02-03T10:00:00Z"
    assert format_to_iso(date_string_1) == iso_format
    assert format_to_iso(date_string_2) == iso_format
    assert format_to_iso(date_string_3) == iso_format
    assert format_to_iso(iso_format) == iso_format


@patch("Elasticsearch_v2.USERNAME", "mock")
@patch("Elasticsearch_v2.PASSWORD", "demisto")
@patch("Elasticsearch_v2.FETCH_INDEX", "customer")
def test_elasticsearch_builder_called_with_username_password(mocker):
    from elasticsearch import Elasticsearch
    from Elasticsearch_v2 import elasticsearch_builder
    es_mock = mocker.patch.object(Elasticsearch, '__init__', return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get('http_auth') == ('mock', 'demisto')
    assert es_mock.call_args[1].get('api_key') is None


def test_elasticsearch_builder_called_with_no_creds(mocker):
    from elasticsearch import Elasticsearch
    from Elasticsearch_v2 import elasticsearch_builder
    es_mock = mocker.patch.object(Elasticsearch, '__init__', return_value=None)
    elasticsearch_builder(None)
    assert es_mock.call_args[1].get('http_auth') is None
    assert es_mock.call_args[1].get('api_key') is None


def test_elasticsearch_parse_subtree():
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
        self.assertEqual(server_response, MOC_ES7_SERVER_RESPONSE)

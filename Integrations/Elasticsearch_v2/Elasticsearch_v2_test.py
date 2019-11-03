from datetime import datetime
from unittest.mock import patch

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
@patch("Elasticsearch_v2.TIME_FORMAT", '%Y-%m-%dT%H:%M:%SZ')
@patch("Elasticsearch_v2.TIME_FIELD", 'Date')
@patch("Elasticsearch_v2.FETCH_INDEX", "users")
def test_incident_creation_e6():
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = datetime.strptime('2019-08-29T14:44:00Z', '%Y-%m-%dT%H:%M:%SZ')
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V6_RESPONSE, last_fetch)

    assert str(last_fetch2) == '2019-08-29 14:46:00'
    assert str(incidents) == MOCK_ES6_INCIDETNS


@patch("Elasticsearch_v2.TIME_METHOD", 'Simple-Date')
@patch("Elasticsearch_v2.TIME_FORMAT", '%Y-%m-%dT%H:%M:%SZ')
@patch("Elasticsearch_v2.TIME_FIELD", 'Date')
@patch("Elasticsearch_v2.FETCH_INDEX", "customer")
def test_incident_creation_e7():
    from Elasticsearch_v2 import results_to_incidents_datetime
    last_fetch = datetime.strptime('2019-08-27T17:59:00Z', '%Y-%m-%dT%H:%M:%SZ')
    incidents, last_fetch2 = results_to_incidents_datetime(ES_V7_RESPONSE, last_fetch)

    assert str(last_fetch2) == '2019-08-27 18:01:00'
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
    last_fetch = int(datetime.strptime('2019-08-27T17:59:00Z', '%Y-%m-%dT%H:%M:%SZ').timestamp())
    incidents, last_fetch2 = results_to_incidents_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, last_fetch)
    assert last_fetch2 == 1572502640
    assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP

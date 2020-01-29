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

PARSED_INDICATOR_HIT = {
    "id": "1d5920f4b44b27a802bd77c4f0536f5a",
    "version": 3,
    "modified": "2020-01-26T14:16:44.641927Z",
    "sortValues": None,
    "account": "acc1",
    "type": "Domain",
    "value": "google.com",
    "rawName": "google.com",
    "createdTime": "2020-01-26T16:16:18.801688+02:00",
    "investigationIDs": [
        "57ec1eb4-454e-4561-8059-a9beb3f830c0"
    ],
    "investigationsCount": 1,
    "sourceInstances": [
        "VirusTotal"
    ],
    "sourceBrands": [
        "VirusTotal"
    ],
    "isIoc": True,
    "lastSeen": "2020-01-26T16:16:18.801508+02:00",
    "firstSeen": "2020-01-26T16:16:18.801509+02:00",
    "lastSeenEntryID": "4@57ec1eb4-454e-4561-8059-a9beb3f830c0",
    "firstSeenEntryID": "4@57ec1eb4-454e-4561-8059-a9beb3f830c0",
    "lastReputationRun": "2020-01-26T16:16:13.219824+02:00",
    "isShared": True,
    "calculatedTime": "2020-01-26T16:16:18.801508+02:00",
    "score": 1,
    "manualSetTime": "0001-01-01T00:00:00Z",
    "context": [],
    "comment": "",
    "CustomFields": None,
    "manuallyEditedFields": None,
    "modifiedTime": "2020-01-26T16:16:09.855733+02:00",
    "moduleToFeedMap": {
        "VirusTotal.VirusTotal": {
            "reliability": "A+ - 3rd party enrichment",
            "rawJSON": None,
            "fetchTime": "2020-01-26T16:16:09.855733+02:00",
            "sourceBrand": "VirusTotal",
            "sourceInstance": "VirusTotal",
            "expirationPolicy": "indicatorType",
            "expirationInterval": 0,
            "expiration": "0001-01-01T00:00:00Z",
            "ExpirationSource": None,
            "bypassExclusionList": False,
            "type": "domain",
            "value": "google.com",
            "score": 1,
            "timestamp": "0001-01-01T00:00:00Z",
            "lastSeen": "0001-01-01T00:00:00Z",
            "firstSeen": "0001-01-01T00:00:00Z",
            "CustomFields": None,
            "modifiedTime": "0001-01-01T00:00:00Z",
            "isEnrichment": True
        },
        "Whois.Whois": {
            "reliability": "A+ - 3rd party enrichment",
            "rawJSON": None,
            "fetchTime": "2020-01-26T16:16:09.855733+02:00",
            "sourceBrand": "VirusTotal",
            "sourceInstance": "VirusTotal",
            "expirationPolicy": "indicatorType",
            "expirationInterval": 0,
            "expiration": "0001-01-01T00:00:00Z",
            "ExpirationSource": None,
            "bypassExclusionList": False,
            "type": "domain",
            "value": "google.com",
            "score": 1,
            "timestamp": "0001-01-01T00:00:00Z",
            "lastSeen": "0001-01-01T00:00:00Z",
            "firstSeen": "0001-01-01T00:00:00Z",
            "CustomFields": None,
            "modifiedTime": "0001-01-01T00:00:00Z",
            "isEnrichment": True
        },
        "Demisto.Demisto": {
            "reliability": "A+ - 3rd party enrichment",
            "rawJSON": None,
            "fetchTime": "2020-01-26T16:16:09.855733+02:00",
            "sourceBrand": "VirusTotal",
            "sourceInstance": "VirusTotal",
            "expirationPolicy": "indicatorType",
            "expirationInterval": 0,
            "expiration": "0001-01-01T00:00:00Z",
            "ExpirationSource": None,
            "bypassExclusionList": False,
            "type": "domain",
            "value": "google.com",
            "score": 1,
            "timestamp": "0001-01-01T00:00:00Z",
            "lastSeen": "0001-01-01T00:00:00Z",
            "firstSeen": "0001-01-01T00:00:00Z",
            "CustomFields": None,
            "modifiedTime": "0001-01-01T00:00:00Z",
            "isEnrichment": False
        }
    },
    "expiration": "0001-01-01T00:00:00Z",
    "expirationStatus": "active",
    "expirationSource": None
}

FEED_IOC_KEYS = (
    'rawJSON',
    'fetchTime',
    'sourceBrand',
    'sourceInstance',
    'expirationPolicy',
    'expirationInterval',
    'expiration',
    'ExpirationSource',
    'bypassExclusionList',
    'type',
    'value',
    'score',
    'timestamp',
    'lastSeen',
    'firstSeen',
    'CustomFields',
    'modifiedTime',
    'isEnrichment'
)


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
    lastfetch = int(datetime.strptime('2019-08-27T17:59:00Z', '%Y-%m-%dT%H:%M:%SZ').timestamp())
    incidents, last_fetch2 = results_to_incidents_timestamp(ES_V7_RESPONSE_WITH_TIMESTAMP, lastfetch)
    assert last_fetch2 == 1572502640
    assert str(incidents) == MOCK_ES7_INCIDENTS_FROM_TIMESTAMP


def test_extract_indicators_from_insight_hit(mocker):
    import Elasticsearch_v2 as es2
    mocker.patch.object(es2, 'results_to_indicator', return_value=PARSED_INDICATOR_HIT)
    ioc_lst = es2.extract_indicators_from_insight_hit(PARSED_INDICATOR_HIT)
    # moduleToFeedMap with isEnrichment: False should not be added to ioc_lst
    assert len(ioc_lst) == 3
    assert ioc_lst[0].get('value')
    # moduleToFeedMap with isEnrichment: False should be added to ioc_lst
    assert ioc_lst[0].get('moduleToFeedMap').get('Demisto.Demisto')
    assert ioc_lst[0].get('moduleToFeedMap').get('VirusTotal.VirusTotal') is None
    set(FEED_IOC_KEYS).issubset(ioc_lst[1])
    set(FEED_IOC_KEYS).issubset(ioc_lst[2])

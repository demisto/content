from unittest.mock import MagicMock
import pytest
from CommonServerPython import *
from dataclasses import dataclass


@dataclass
class MockClient:
    time_field = "calculatedTime"


class MockHit:
    def __init__(self, hit_val):
        self._hit_val = dict(hit_val)

    def to_dict(self):
        return self._hit_val


"""MOCKED RESPONSES"""

CUSTOM_VAL_KEY = 'indicatorValue'

CUSTOM_TYPE_KEY = 'indicatorType'

CUSTOM_HIT = {
    CUSTOM_VAL_KEY: '5.5.5.5',
    CUSTOM_TYPE_KEY: 'IP'
}

CUSTOM_HIT_ELASTIC_V7 = {
    "_source": {
        CUSTOM_VAL_KEY: '5.5.5.5',
        CUSTOM_TYPE_KEY: 'IP'
    }}

INSIGHT_HIT_ELASTIC_V7 = {
    "_source": {
        "name": '5.5.5.5',
        "type": 'IP'
    }}

PARSED_INSIGHT_HIT_ELASTIC_V7 = {
    'name': '5.5.5.5',
    'type': 'IP',
    'value': '5.5.5.5',
    'rawJSON': {
        'name': '5.5.5.5',
        'type': 'IP',
        'value': '5.5.5.5'
    },
    'fields': {}
}

PARSED_CUSTOM_HIT = {
    'indicatorValue': '5.5.5.5',
    'indicatorType': 'IP',
    'value': '5.5.5.5',
    'rawJSON': {
        'indicatorValue': '5.5.5.5',
        'indicatorType': 'IP',
        'value': '5.5.5.5'
    },
    'type': 'IP',
    'fields': {'tags': ['tag1', 'tag2'], 'trafficlightprotocol': 'AMBER'}
}

PARSED_INSIGHT_HIT = {
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
    "expirationSource": None,
    'fields': {'tags': ['tag1', 'tag2'], 'trafficlightprotocol': 'AMBER'}
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
    'isEnrichment',
    'fields'
)


def test_hit_to_indicator():
    import FeedElasticsearch as esf
    ioc = esf.hit_to_indicator(MockHit(CUSTOM_HIT), CUSTOM_VAL_KEY, CUSTOM_TYPE_KEY, None, ['tag1', 'tag2'], 'AMBER')
    assert ioc == PARSED_CUSTOM_HIT

    no_type_hit = dict(CUSTOM_HIT)
    no_type_hit[CUSTOM_TYPE_KEY] = ''
    ioc = esf.hit_to_indicator(MockHit(no_type_hit), CUSTOM_VAL_KEY, CUSTOM_TYPE_KEY, 'IP', ['tag1', 'tag2'], 'AMBER')
    assert ioc['type'] == 'IP'
    assert ioc[CUSTOM_TYPE_KEY] == ''

    ioc = esf.hit_to_indicator(MockHit(CUSTOM_HIT), CUSTOM_VAL_KEY, '', 'URL', ['tag1', 'tag2'], 'AMBER')
    assert ioc['type'] == 'URL'


def test_hit_to_indicator_enrichment_excluded():
    """
    Given:
        - The `hit_to_indicator` function in the `FeedElasticsearch` module is used to convert a hit to an indicator.
    When:
        - Enrichment excluded is True
    Then:
        - 'enrichmentExcluded' = True should be added to the indicator.
    """
    import FeedElasticsearch as esf
    ioc = esf.hit_to_indicator(MockHit(CUSTOM_HIT), CUSTOM_VAL_KEY, CUSTOM_TYPE_KEY, None, ['tag1', 'tag2'], 'AMBER',
                               enrichment_excluded=True)
    assert ioc.pop('enrichmentExcluded')
    assert ioc == PARSED_CUSTOM_HIT


def test_hit_to_indicator_custom_elastic_v7(mocker):
    """
    Background:
    To maintain backwards compatibility for elastic server v7 and below, we have changed several places in the code where instead
    of using the elasticsearch_dsl library (which is compatible to versions >= 8 we use the elasticsearch library directly).
    In some cases those code changes caused slight differences in API responses structure.

    In this test we check that the 'hit_to_indicator' function handles the generic (custom) hit object structure we get when
    searching for indicators hits in Elasticsearch server v7.

    Given:
        - Elasticsearch client from type 'Elasticsearch' (v7 client), and a mock response of a generic (custom) hit object we get
        by querying elasticsearch v7 server.
    When:
        - Running the 'hit_to_indicator' function.
    Then:
        - Make sure that the parsed hit is as expected.
    """
    params: dict = {'client_type': 'ElasticSearch'}
    mocker.patch.object(demisto, 'params', return_value=params)
    import FeedElasticsearch as esf
    ioc = esf.hit_to_indicator(CUSTOM_HIT_ELASTIC_V7, CUSTOM_VAL_KEY, CUSTOM_TYPE_KEY, None, ['tag1', 'tag2'], 'AMBER')
    assert ioc == PARSED_CUSTOM_HIT


def test_hit_to_indicator_insight_hit_v7():
    """
    Background:
    To maintain backwards compatibility for elastic server v7 and below, we have changed several places in the code where instead
    of using the elasticsearch_dsl library (which is compatible to versions >= 8 we use the elasticsearch library directly).
    In some cases those code changes caused slight differences in API responses structure.

    In this test we check that the 'hit_to_indicator' function handles the demisto (insight) hit object structure we get when
    searching for indicators hits in Elasticsearch server v7.

    Given:
        - Elasticsearch client from type 'Elasticsearch' (v7 client), and a mock response of a demisto (insight) hit object we get
          by querying elasticsearch v7 server.
    When:
        - Running the 'hit_to_indicator' function.
    Then:
        - Make sure that the parsed hit is as expected.
    """
    import FeedElasticsearch as esf
    ioc = esf.hit_to_indicator(INSIGHT_HIT_ELASTIC_V7)
    assert ioc == PARSED_INSIGHT_HIT_ELASTIC_V7


def test_extract_indicators_from_insight_hit2(mocker):
    params: dict = {'client_type': 'OpenSearch'}
    mocker.patch.object(demisto, 'params', return_value=params)
    import FeedElasticsearch as esf
    mocker.patch.object(esf, 'hit_to_indicator', return_value=dict(PARSED_INSIGHT_HIT))
    ioc_lst, ioc_enrch_lst = esf.extract_indicators_from_insight_hit(PARSED_INSIGHT_HIT, ['tag1', 'tag2'], 'AMBER')
    # moduleToFeedMap with isEnrichment: False should not be added to ioc_lst
    assert len(ioc_lst) == 1
    assert len(ioc_enrch_lst[0]) == 2
    assert ioc_lst[0].get('value')
    # moduleToFeedMap with isEnrichment: False should be added to ioc_lst
    assert ioc_lst[0].get('moduleToFeedMap').get('Demisto.Demisto')
    assert ioc_lst[0].get('moduleToFeedMap').get('VirusTotal.VirusTotal') is None
    set(FEED_IOC_KEYS).issubset(ioc_enrch_lst[0][0])
    set(FEED_IOC_KEYS).issubset(ioc_enrch_lst[0][1])


def test_extract_indicators_from_generic_hit(mocker):
    import FeedElasticsearch as esf
    mocker.patch.object(esf, 'hit_to_indicator', return_value=PARSED_CUSTOM_HIT)
    ioc_lst = esf.extract_indicators_from_generic_hit(CUSTOM_HIT, CUSTOM_VAL_KEY, CUSTOM_TYPE_KEY, None,
                                                      ['tag1', 'tag2'], 'AMBER')
    assert ioc_lst == [PARSED_CUSTOM_HIT]


def test_create_enrichment_batches_one_indicator(mocker):
    import FeedElasticsearch as esf
    mocker.patch.object(esf, 'hit_to_indicator', return_value=PARSED_INSIGHT_HIT)
    _, ioc_enrch_lst = esf.extract_indicators_from_insight_hit(PARSED_INSIGHT_HIT, ['tag1', 'tag2'], 'AMBER')
    ioc_enrch_lst_of_lsts = esf.create_enrichment_batches(ioc_enrch_lst)
    assert len(ioc_enrch_lst_of_lsts) == 2
    assert ioc_enrch_lst_of_lsts[0][0] == ioc_enrch_lst[0][0]
    assert ioc_enrch_lst_of_lsts[1][0] == ioc_enrch_lst[0][1]


def test_create_enrichment_batches_mult_indicators():
    import FeedElasticsearch as esf
    ioc_enrch_lst = [
        [1, 2, 3],
        [4, 5],
        [6, 7, 8, 9]
    ]
    ioc_enrch_lst_of_lsts = esf.create_enrichment_batches(ioc_enrch_lst)
    assert len(ioc_enrch_lst_of_lsts) == 4
    assert ioc_enrch_lst_of_lsts[0] == [1, 4, 6]
    assert ioc_enrch_lst_of_lsts[1] == [2, 5, 7]
    assert ioc_enrch_lst_of_lsts[2] == [3, 8]
    assert ioc_enrch_lst_of_lsts[3] == [9]


def test_elasticsearch_builder_called_with_username_password(mocker):
    """
    Given:
        - basic authentication parameters are provided (username and password)
        - Client type is Elasticsearch (elastic v7)
    When:
        - creating an Elasticsearch client
    Then:
        - ensure the client is created with the correct parameters
    """
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new="Elasticsearch")
    es_mock = mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    username = 'demisto'
    password = 'mock'
    esf.ElasticsearchClient(username=username, password=password)
    assert es_mock.call_args[1].get('http_auth') == ('demisto', 'mock')
    assert es_mock.call_args[1].get('api_key') is None


def test_elasticsearch_builder_called_with_username_password_elastic_v8(mocker):
    """
    In elastic version >= 8, basic auth params are transferred through the 'basic auth' key instead of the 'http_auth' key.
    This test check that the parameters are transferred correctly.
    Given:
        - basic authentication parameters are provided (username and password)
        - Client type is Elasticsearch_v8
    When:
        - creating an Elasticsearch client
    Then:
        - ensure the client is created with the correct parameters
    """
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new="Elasticsearch_v8")
    es_mock = mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    username = 'demisto'
    password = 'mock'
    esf.ElasticsearchClient(username=username, password=password)
    assert es_mock.call_args[1].get('basic_auth') == ('demisto', 'mock')
    assert es_mock.call_args[1].get('http_auth') is None
    assert es_mock.call_args[1].get('api_key') is None


def test_elasticsearch_builder_called_with_api_key(mocker):
    """
    Given:
        - api key authentication parameters are provided (api key id and api key)
    When:
        - creating an Elasticsearch client
    Then:
        - ensure the client is created with the correct parameters
    """
    import FeedElasticsearch as esf
    es_mock = mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    api_id = 'demisto'
    api_key = 'mock'
    esf.ElasticsearchClient(api_key=api_key, api_id=api_id)
    assert es_mock.call_args[1].get('http_auth') is None
    assert es_mock.call_args[1].get('api_key') == (api_id, api_key)


def test_elasticsearch_builder_called_with_no_creds(mocker):
    """
    Given:
        - no authentication parameter are provided
    When:
        - creating an Elasticsearch client
    Then:
        - ensure the client is created with the correct parameters (edge this, this use-case should not happen as '401
          Unauthorized - Incorrect or invalid username or password' message will be returned
    """
    import FeedElasticsearch as esf
    es_mock = mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    esf.ElasticsearchClient()
    assert es_mock.call_args[1].get('http_auth') is None
    assert es_mock.call_args[1].get('api_key') is None


def test_extract_api_from_username_password_empty():
    import FeedElasticsearch as esf
    assert esf.extract_api_from_username_password(None, None) == (None, None)


def test_extract_api_from_username_password_username_username():
    import FeedElasticsearch as esf
    assert esf.extract_api_from_username_password('username', 'password') == (None, None)


def test_extract_api_from_username_password_username_api_key():
    import FeedElasticsearch as esf
    username = esf.API_KEY_PREFIX + 'api_id'
    assert esf.extract_api_from_username_password(username, 'api_key') == ('api_id', 'api_key')


def test_last_run():
    from FeedElasticsearch import update_last_fetch
    ioc_lst = [{"id": "1", "calculatedTime": "2023-01-17T14:30:00.000Z"},
               {"id": "2", "calculatedTime": "2023-01-17T14:32:00.000Z"},
               {"id": "3", "calculatedTime": "2023-01-17T14:33:00.000Z"},
               {"id": "4", "calculatedTime": "2023-01-17T14:33:00.000Z"}]
    last_update, last_ids = update_last_fetch(MockClient(), ioc_lst)
    assert set(last_ids) == {"4", "3"}
    assert datetime.fromtimestamp(last_update // 1000).isoformat() == "2023-01-17T14:33:00"


@pytest.mark.parametrize(
    'client_version',
    [
        ("Elasticsearch"),
        ("OpenSearch"),
        ("Elasticsearch_v8")
    ]
)
def test_get_indicators_by_elastic_version_generic_feed(mocker, client_version):
    """
    This test makes sure that the right get generic indicators functions are called in accordance to the elasticsearch
    client version.

    Given:
        - Elasticsearch client of type:
            1. Elasticsearch (elastic version <= 7)
            2. OpenSearch
            3. Elasticsearch_v8
    When:
        - Running the 'get_indicators_command'.
    Then:
        - Verify that the right get indicators inner function is being called:
            1. The 'get_generic_indicators_elastic_v7' is called.
            2. The 'get_generic_indicators' is called.
            3. The 'get_generic_indicators' is called.
    """
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new=client_version)
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocker.patch.object(esf, 'get_scan_generic_format', return_value=None)
    mock_get_generic_indicators = mocker.patch.object(esf, 'get_generic_indicators', return_value=None)
    mock_get_generic_indicators_elastic_v7 = mocker.patch.object(esf, 'get_generic_indicators_elastic_v7', return_value=None)

    client = esf.ElasticsearchClient()
    esf.get_indicators_command(client, feed_type='Generic Feed',
                               src_val='indicatorValue', src_type='indicatorType', default_type="IP")

    if client_version in ['Elasticsearch_v8', 'OpenSearch']:
        assert mock_get_generic_indicators.call_count == 1
        assert mock_get_generic_indicators_elastic_v7.call_count == 0
    else:  # Elasticsearch v7 and below
        assert mock_get_generic_indicators.call_count == 0
        assert mock_get_generic_indicators_elastic_v7.call_count == 1


@pytest.mark.parametrize(
    'client_version',
    [
        ("Elasticsearch"),
        ("OpenSearch"),
        ("Elasticsearch_v8")
    ]
)
def test_get_indicators_by_elastic_version_demisto_feed(mocker, client_version):
    """
    This test makes sure that the right get demisto (insight) indicators functions are called in accordance to the elasticsearch
    client version.

    Given:
        - Elasticsearch client of type:
            1. Elasticsearch (elastic version <= 7)
            2. OpenSearch
            3. Elasticsearch_v8
    When:
        - Running the 'get_indicators_command'.
    Then:
        - Verify that the right get indicators inner function is being called:
            1. The 'get_demisto_indicators_elastic_v7' is called.
            2. The 'get_demisto_indicators' is called.
            3. The 'get_demisto_indicators' is called.
    """
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new=client_version)
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocker.patch.object(esf, 'get_scan_insight_format', return_value=None)
    mock_get_demisto_indicators = mocker.patch.object(esf, 'get_demisto_indicators', return_value=([], []))
    mock_get_demisto_indicators_elastic_v7 = mocker.patch.object(esf, 'get_demisto_indicators_elastic_v7',
                                                                 return_value=([], []))

    client = esf.ElasticsearchClient()
    esf.get_indicators_command(client, feed_type='Cortex XSOAR MT Shared Feed', src_val='', src_type='', default_type='')

    if client_version in ['Elasticsearch_v8', 'OpenSearch']:
        assert mock_get_demisto_indicators.call_count == 1
        assert mock_get_demisto_indicators_elastic_v7.call_count == 0
    else:  # Elasticsearch v7 and below
        assert mock_get_demisto_indicators.call_count == 0
        assert mock_get_demisto_indicators_elastic_v7.call_count == 1


@pytest.mark.parametrize(
    'client_version',
    [
        ("Elasticsearch"),
        ("OpenSearch"),
        ("Elasticsearch_v8")
    ]
)
def test_fetch_indicators_by_elastic_version(mocker, client_version):
    """
    This test makes sure that the right fetch indicators functions are called in accordance to the elasticsearch client version.

    Given:
        - Elasticsearch client of type:
            1. Elasticsearch (elastic version <= 7)
            2. OpenSearch
            3. Elasticsearch_v8
    When:
        - Running the 'fetch_indicators_command'.
    Then:
        - Verify that the right get indicators inner function is being called:
            1. The 'fetch_indicators_elastic_v7' is called.
            2. The 'fetch_indicators' is called.
            3. The 'fetch_indicators' is called.
    """
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new=client_version)
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocker.patch.object(esf, 'get_last_fetch_timestamp', return_value=None)
    mock_fetch_indicators = mocker.patch.object(esf, 'fetch_indicators', return_value=([], []))
    mock_fetch_indicators_elastic_v7 = mocker.patch.object(esf, 'fetch_indicators_elastic_v7', return_value=([], []))

    client = esf.ElasticsearchClient()
    esf.fetch_indicators_command(client, feed_type='Generic Feed',
                                 src_val='indicatorValue', src_type='indicatorType', default_type="IP",
                                 last_fetch={}, fetch_limit=1000)

    if client_version in ['Elasticsearch_v8', 'OpenSearch']:
        assert mock_fetch_indicators.call_count == 1
        assert mock_fetch_indicators_elastic_v7.call_count == 0
    else:  # Elasticsearch v7 and below
        assert mock_fetch_indicators.call_count == 0
        assert mock_fetch_indicators_elastic_v7.call_count == 1


def test_get_demisto_indicators_elastic_v7(mocker):
    """
    Tests the 'get_demisto_indicators_elastic_v7' function's logic.

    Given:
        - Elasticsearch client of type Elasticsearch (v7 and below), a mocked response of the FeedElasticsearch.scan
          api call (generator).
    When:
        - Running the 'get_demisto_indicators_elastic_v7'.
    Then:
        - Verify that the indicators' list is as expected.

    """
    import FeedElasticsearch as esf
    mocked_scan_indicators_res_e7 = [
        {'_index': 'index_name',
         '_type': '_doc',
         '_id': '1',
         '_score': None,
         '_source': {
             'name': '7.7.7.7',
             'calculatedTime': '2020-01-12T15:29:01.270228+02:00',
             'id': '1',
             'type': 'IP',
         },
         'sort': [3]
         }
    ]
    mocked_generator = MagicMock()
    mocked_generator.return_value = (x for x in mocked_scan_indicators_res_e7)
    mocker.patch('FeedElasticsearch.scan', return_value=mocked_generator.return_value)
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)

    client = esf.ElasticsearchClient()
    client.time_field = 'calculatedTime'
    search = esf.get_scan_insight_format(client, feed_type='Cortex XSOAR MT Shared Feed')

    ioc_lst, _ = esf.get_demisto_indicators_elastic_v7(client, search, None, None, None)

    assert len(ioc_lst) == 1
    assert ioc_lst[0]['name'] == '7.7.7.7'
    assert ioc_lst[0]['id'] == '1'
    assert ioc_lst[0]['calculatedTime'] == '2020-01-12T15:29:01.270228+02:00'
    assert ioc_lst[0]['type'] == 'IP'
    assert ioc_lst[0]['value'] == '7.7.7.7'


def test_get_generic_indicators_elastic_v7(mocker):
    """
    Tests the 'get_generic_indicators_elastic_v7' function's logic.

    Given:
        - Elasticsearch client of type Elasticsearch (v7 and below), a mocked response of the FeedElasticsearch.scan
          api call (generator).
    When:
        - Running the 'get_generic_indicators_elastic_v7'.
    Then:
        - Verify that the indicators' list is as expected.

    """
    import FeedElasticsearch as esf
    mocked_scan_indicators_res_e7 = [
        {'_index': 'index_name',
         '_type': '_doc',
         '_id': '1',
         '_score': None,
         '_source': {
             'indicatorValue': '1.1.1.1',
             'date': '2020-01-12T15:29:01.270228+02:00',
             'id': '1',
             'indicatorType': 'IP',
         },
         'sort': [3]
         }
    ]
    mocked_generator = MagicMock()
    mocked_generator.return_value = (x for x in mocked_scan_indicators_res_e7)
    mocker.patch('FeedElasticsearch.scan', return_value=mocked_generator.return_value)
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)

    client = esf.ElasticsearchClient()
    client.time_field = 'date'
    search = esf.get_scan_generic_format(client)

    ioc_lst = esf.get_generic_indicators_elastic_v7(client, search, 'indicatorValue', 'indicatorType', 'IP', None, None, None)

    assert len(ioc_lst) == 1
    assert ioc_lst[0]['indicatorValue'] == '1.1.1.1'
    assert ioc_lst[0]['id'] == '1'
    assert ioc_lst[0]['date'] == '2020-01-12T15:29:01.270228+02:00'
    assert ioc_lst[0]['indicatorType'] == 'IP'
    assert ioc_lst[0]['value'] == '1.1.1.1'


def test_fetch_demisto_indicators_elastic_v7(mocker):
    """
    Tests the 'fetch_indicators_elastic_v7' function's logic for feed type - Demisto Feed.

    Given:
        - Elasticsearch client of type Elasticsearch (v7 and below), a mocked response of the FeedElasticsearch.search api call.
    When:
        - Running the 'fetch_indicators_elastic_v7'.
    Then:
        - Verify that the indicators' list is as expected.
    """
    import FeedElasticsearch as esf
    mocked_search_indicators_res_e7 = {'took': 1,
                                       'timed_out': False,
                                       '_shards':
                                           {'total': 1,
                                            'successful': 1,
                                            'skipped': 0,
                                            'failed': 0
                                            },
                                       'hits': {
                                           'total': {'value': 1, 'relation': 'eq'},
                                           'max_score': None,
                                           'hits': [
                                               {'_index': 'index_name',
                                                '_type': '_doc',
                                                '_id': '1',
                                                '_score': None,
                                                '_source':
                                                    {'id': '1',
                                                     'version': 1,
                                                     'modified': '2020-01-12T13:27:02.270302Z',
                                                     'sortValues': None,
                                                     'comments': [],
                                                     'account': '',
                                                     'type': 'IP',
                                                     'name': '1.1.1.1',
                                                     'value': '1.1.1.1',
                                                     'rawName': '1.1.1.1',
                                                     'createdTime': '2020-01-12T15:27:02.270303+02:00',
                                                     'investigationIDs': [],
                                                     'investigationsCount': 0,
                                                     'isIoc': True,
                                                     'lastSeen': '2020-01-12T15:27:02.270228+02:00',
                                                     'firstSeen': '2020-01-12T15:27:02.270228+02:00',
                                                     'lastSeenEntryID': 'API',
                                                     'firstSeenEntryID': 'API',
                                                     'lastReputationRun': '0001-01-01T00:00:00Z',
                                                     'isShared': False,
                                                     'calculatedTime': '2020-01-12T15:27:02.270228+02:00',
                                                     'manualSetTime': '0001-01-01T00:00:00Z',
                                                     'context': None,
                                                     'comment': '',
                                                     'CustomFields': {'internal': False},
                                                     'ManuallyEditedFields': None,
                                                     'modifiedTime': '0001-01-01T00:00:00Z',
                                                     'expiration': '0001-01-01T00:00:00Z',
                                                     'expirationStatus': 'active',
                                                     'expirationSource': {
                                                         'setTime': '2020-01-12T15:27:02.27023+02:00',
                                                         'source': 'indicatorType',
                                                         'user': '', 'feedId': '',
                                                         'expirationPolicy': 'never',
                                                         'expirationInterval': 0
                                                     }
                                                     },
                                                'sort': [1578835622270]
                                                },
                                           ]
                                       }
                                       }
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocker.patch.object(esf.Elasticsearch, 'search', return_value=mocked_search_indicators_res_e7)

    client = esf.ElasticsearchClient()
    client.time_field = 'calculatedTime'
    client.fetch_index = 'test'

    ioc_lst, _ = esf.fetch_indicators_elastic_v7(client, last_fetch_timestamp="", feed_type='Cortex XSOAR MT Shared Feed',
                                                 fetch_limit=10000, src_type=None, src_val=None, default_type=None)

    assert len(ioc_lst) == 1
    assert ioc_lst[0]['name'] == '1.1.1.1'
    assert ioc_lst[0]['id'] == '1'
    assert ioc_lst[0]['calculatedTime'] == '2020-01-12T15:27:02.270228+02:00'
    assert ioc_lst[0]['type'] == 'IP'
    assert ioc_lst[0]['value'] == '1.1.1.1'


def test_fetch_generic_indicators_elastic_v7_with_time_field(mocker):
    """
    Tests the 'fetch_indicators_elastic_v7' function's logic for feed type - Generic Feed, when the user set a custom time field.
    When a time field is set, we fetch by searching for indicators in relation to the last fetch time which is determined by the
    time field values of the indicators that were fetched in the last cycle.

    Given:
        - Elasticsearch client of type Elasticsearch (v7 and below), a mocked response of the FeedElasticsearch.search api call.
          client.time_field is set and equals "date".
    When:
        - Running the 'fetch_indicators_elastic_v7'.
    Then:
        - Verify that the indicators' list is as expected.
    """
    import FeedElasticsearch as esf
    mocked_search_indicators_res_e7 = {'took': 0,
                                       'timed_out': False,
                                       '_shards': {'total': 1, 'successful': 1, 'skipped': 0, 'failed': 0},
                                       'hits': {'total': {'value': 2, 'relation': 'eq'},
                                                'max_score': None,
                                                'hits': [{'_index': 'test',
                                                          '_type': '_doc',
                                                          '_id': '1111',
                                                          '_score': None,
                                                          '_source': {'indicatorValue': 'https://www.test.com/',
                                                                      'indicatorType': 'URL',
                                                                      'date': '2024-10-14T16:03:45.735577',
                                                                      'id': '1111'},
                                                          'sort': [1728921825735]},
                                                         {'_index': 'test',
                                                          '_type': '_doc',
                                                          '_id': '2222',
                                                          '_score': None,
                                                          '_source': {'indicatorValue': "1.1.1.1",
                                                                      'indicatorType': 'IP',
                                                                      'date': '2024-10-14T16:05:55.735588',
                                                                      'id': '2222'},
                                                          'sort': [1728921955735]}]}}
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocker.patch.object(esf.Elasticsearch, 'search', return_value=mocked_search_indicators_res_e7)

    client = esf.ElasticsearchClient()
    client.time_field = 'date'
    client.fetch_index = 'test'

    ioc_lst, _ = esf.fetch_indicators_elastic_v7(client, last_fetch_timestamp="", feed_type='Generic Feed',
                                                 fetch_limit=10000, src_type='indicatorType', src_val='indicatorValue',
                                                 default_type='IP')

    assert len(ioc_lst) == 2
    assert ioc_lst[0]['indicatorValue'] == 'https://www.test.com/'
    assert ioc_lst[0]['id'] == '1111'
    assert ioc_lst[0]['date'] == '2024-10-14T16:03:45.735577'
    assert ioc_lst[0]['indicatorType'] == 'URL'
    assert ioc_lst[0]['value'] == 'https://www.test.com/'
    assert ioc_lst[1]['indicatorValue'] == '1.1.1.1'
    assert ioc_lst[1]['id'] == '2222'
    assert ioc_lst[1]['date'] == '2024-10-14T16:05:55.735588'
    assert ioc_lst[1]['indicatorType'] == 'IP'
    assert ioc_lst[1]['value'] == '1.1.1.1'


def test_fetch_generic_indicators_elastic_v7_without_time_field(mocker):
    """
    Tests the 'fetch_indicators_elastic_v7' function's logic for feed type - Generic Feed, without a custom time field.
    When a time field isn't set, we fetch by scanning for all indicators regardless last fetch time (in every fetch cycle).

    Given:
        - Elasticsearch client of type Elasticsearch (v7 and below), a mocked response of the FeedElasticsearch.scan api call.
          client.time_field isn't set.
    When:
        - Running the 'fetch_indicators_elastic_v7'.
    Then:
        - Verify that the indicators' list is as expected.
    """
    import FeedElasticsearch as esf
    mocked_scan_indicators_res_e7 = [
        {'_index': 'test',
         '_type': '_doc',
         '_id': '1',
         '_score': None,
         '_source': {
             'indicatorValue': '1.1.1.1',
             'date': '2020-01-12T15:29:01.270228+02:00',
             'id': '1',
             'indicatorType': 'IP',
         },
         'sort': [3]
         },
        {'_index': 'test',
         '_type': '_doc',
         '_id': '2',
         '_score': None,
         '_source': {
             'indicatorValue': 'https://www.test.com/',
             'date': '2020-01-12T15:29:01.270228+02:00',
             'id': '2',
             'indicatorType': 'URL',
         },
         'sort': [3]
         }
    ]
    mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    mocked_generator = MagicMock()
    mocked_generator.return_value = (x for x in mocked_scan_indicators_res_e7)
    mocker.patch('FeedElasticsearch.scan', return_value=mocked_generator.return_value)

    client = esf.ElasticsearchClient()
    client.fetch_index = 'test'

    ioc_lst, _ = esf.fetch_indicators_elastic_v7(client, last_fetch_timestamp="", feed_type='Generic Feed',
                                                 fetch_limit=10000, src_type='indicatorType', src_val='indicatorValue',
                                                 default_type='IP')

    assert len(ioc_lst) == 2
    assert ioc_lst[0]['indicatorValue'] == '1.1.1.1'
    assert ioc_lst[0]['id'] == '1'
    assert ioc_lst[0]['date'] == '2020-01-12T15:29:01.270228+02:00'
    assert ioc_lst[0]['indicatorType'] == 'IP'
    assert ioc_lst[0]['value'] == '1.1.1.1'
    assert ioc_lst[1]['indicatorValue'] == 'https://www.test.com/'
    assert ioc_lst[1]['id'] == '2'
    assert ioc_lst[1]['date'] == '2020-01-12T15:29:01.270228+02:00'
    assert ioc_lst[1]['indicatorType'] == 'URL'
    assert ioc_lst[1]['value'] == 'https://www.test.com/'


@pytest.mark.parametrize('server_details, server_version, client_version',
                         [
                             ({'name': 'test1',
                               'cluster_name': 'elasticsearch',
                               'cluster_uuid': 'test_id',
                               'version': {'number': '7.3.0', }},
                              '7.3.0', 'Elasticsearch_v8'),
                             ({'name': 'test2',
                               'cluster_name': 'elasticsearch',
                               'cluster_uuid': 'test_id',
                               'version': {'number': '8.4.1', }},
                              '8.4.1', 'Elasticsearch')],
                         ids=[
                             "Test miss configuration error - server version is 7 while client version is 8",
                             "Test miss configuration error - server version is 8 while client version is 7"]
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
    import FeedElasticsearch as esf
    mocker.patch('FeedElasticsearch.ELASTIC_SEARCH_CLIENT', new=client_version)
    with pytest.raises(ValueError) as e:
        esf.verify_es_server_version(server_details)
    assert server_version in str(e.value)


def test_feed_main_enrichment_excluded(mocker):
    """
        Given: params with tlp_color set to RED and enrichmentExcluded set to False
        When: Calling feed_main
        Then: validate enrichment_excluded is set to True
    """
    from FeedElasticsearch import main

    params = {
        'tlp_color': 'RED',
        'enrichmentExcluded': False,
        'time_field': 'test',
        'feed_type': ['test']
    }

    client_mocker = mocker.patch('FeedElasticsearch.ElasticsearchClient')
    mocker.patch('FeedElasticsearch.extract_api_from_username_password', return_value=('test', 'test'))

    mocker.patch('FeedElasticsearch.is_xsiam_or_xsoar_saas', return_value=True)
    mocker.patch.object(demisto, 'params', return_value=params)

    # Call the function under test
    main()

    # Assertion - verify that enrichment_excluded is set to True
    assert client_mocker.call_args_list[0].args[-1] is True

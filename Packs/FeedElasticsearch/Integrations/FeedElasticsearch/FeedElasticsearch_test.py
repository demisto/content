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
    When:
        - creating an Elasticsearch client
    Then:
        - ensure the client is created with the correct parameters
    """
    import FeedElasticsearch as esf
    es_mock = mocker.patch.object(esf.Elasticsearch, '__init__', return_value=None)
    username = 'demisto'
    password = 'mock'
    esf.ElasticsearchClient(username=username, password=password)
    assert es_mock.call_args[1].get('http_auth') == ('demisto', 'mock')
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

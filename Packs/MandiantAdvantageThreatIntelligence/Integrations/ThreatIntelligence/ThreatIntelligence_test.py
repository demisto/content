import json
import io
import freezegun
import pytest
from CommonServerPython import *
from ThreatIntelligence import MandiantClient


def test_retrieve_token(mocker):
    """
        Given -
           client
        When -
            generating a token
        Then -
            Validate the result is as expected
    """
    MandiantClient._http_request = lambda _, *args, **kwargs: {'access_token': 'token', 'expires_in': 1666749807}
    client = MandiantClient('url', 'username', 'password', False, False, 60, '90 days', 1, ['Malware'])

    mocker.patch.object(client, '_http_request', return_value={'access_token': 'token', 'expires_in': 1666749807})
    res = client._retrieve_token()
    assert res == 'token'


def mock_client():
    MandiantClient._retrieve_token = lambda x: 'token'
    client = MandiantClient('url', 'username', 'password', False, False, 60, '90 days', 1, ['Malware'])
    return client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@freezegun.freeze_time('2020-11-25T11:57:28Z')
def test_get_token():
    """
        Given -
           client
        When -
            getting a token
        Then -
            Validate the result is as expected
    """
    from ThreatIntelligence import MandiantClient
    MandiantClient._retrieve_token = lambda x: 'token'
    client = MandiantClient('url', 'username', 'password', False, False, 60, 'x_app_name', 'first_fetch', 1, [])
    res = client._get_token()
    assert res == 'token'


@pytest.mark.parametrize('info_type, response, result',
                         [('info-type', {'info-type': 'res'}, 'res'),
                          ('', {'info-type': 'res'}, {'info-type': 'res'}),
                          ('attack-pattern', {}, []),
                          ('attack-pattern', {'malware': [{'attack-patterns': {'res': {}}}]}, ['res'])])
def test_get_indicator_additional_info(mocker, info_type, response, result):
    client = mock_client()
    mocker.patch.object(client, '_http_request', return_value=response)
    res = client.get_indicator_info('identifier', 'Malware', info_type)
    assert res == result


def test_get_indicators_valid(mocker):
    client = mock_client()
    mocker.patch.object(client, '_http_request', return_value={'malware': ['list']})
    res = client.get_indicators('Malware')
    assert res == ['list']


def test_get_indicators_invalid(mocker):
    from ThreatIntelligence import DemistoException
    client = mock_client()
    mocker.patch.object(client, '_http_request', side_effect=DemistoException('exception'))
    res = client.get_indicators('Malware')
    assert res == []


INDICATOR_LIST = [{'last_updated': '2020-11-23T11:57:28Z'}, {'last_updated': '2020-11-24T11:57:28Z'}]


@pytest.mark.parametrize('indicator_type, result',
                         [('Indicators', INDICATOR_LIST),
                          ('Malware', INDICATOR_LIST[::-1])])
@freezegun.freeze_time('2020-11-25T11:57:28Z')
def test_get_new_indicators(mocker, indicator_type, result):
    from ThreatIntelligence import get_new_indicators
    client = mock_client()
    mocker.patch.object(client, 'get_indicators', return_value=INDICATOR_LIST)
    res = get_new_indicators(client, '90 days ago', indicator_type, 10)
    assert res == result


@pytest.mark.parametrize('mscore, res', [(None, 0), ('1', 1), ('22', 0), ('52', 2), ('82', 3), ('101', 0)])
def test_get_verdict(mscore, res):
    """
        Given -
           mscore
        When -
            get_verdict
        Then -
            receive valid verdict for each mscore
    """
    from ThreatIntelligence import get_verdict
    assert get_verdict(mscore) == res


def test_get_indicator_relationships():
    from ThreatIntelligence import get_indicator_relationships, EntityRelationship
    res = get_indicator_relationships({'field_indicator': [{'entity_b_field': 'value_b'}],
                                       'entity_a_field': 'value_a'}, 'field_indicator',
                                      'entity_a_field', 'entity_a_type', 'entity_b_field', 'entity_b_type',
                                      EntityRelationship.Relationships.RELATED_TO,
                                      EntityRelationship.Relationships.RELATED_TO)
    assert len(res) == 1
    assert res[0]['entityA'] == 'value_a'
    assert res[0]['entityAType'] == 'entity_a_type'
    assert res[0]['entityB'] == 'value_b'
    assert res[0]['entityBType'] == 'entity_b_type'
    assert res[0]['name'] == 'related-to'
    assert res[0]['reverseName'] == 'related-to'


BASIC_INDICATOR = {
    'operating_systems': 'operatingsystemrefs',
    'aliases': 'redacted',
    'capabilities': 'capabilities',
    'industries': [{'name': 'tags'}],
    'detections': 'mandiantdetections',
    'yara': [{'name': 'name', 'id': 'id'}],
    'roles': 'roles',
    'id': 'stixid',
    'name': 'name',
    'description': 'description',
    'last_updated': 'updateddate',
    'last_activity_time': 'lastseenbysource',
    'actors': [],
    'cve': [],
    'mscore': 100,
    'motivations': [{'name': 'primarymotivation'}],
    'locations': {'target': [{'name': 'target'}]}

}


def test_create_malware_indicator():
    from ThreatIntelligence import create_malware_indicator
    client = mock_client()
    res = create_malware_indicator(client, BASIC_INDICATOR)
    assert res['value'] == 'name'
    assert res['type'] == 'Malware'
    assert len(res['fields']) == 12


def test_create_actor_indicator():
    from ThreatIntelligence import create_actor_indicator
    client = mock_client()
    res = create_actor_indicator(client, BASIC_INDICATOR)
    assert res['value'] == 'name'
    assert res['type'] == 'Threat Actor'
    assert len(res['fields']) == 7


@freezegun.freeze_time('2020-11-25T11:57:28Z')
def test_fetch_indicators(mocker):
    from ThreatIntelligence import fetch_indicators
    client = mock_client()
    mocker.patch.object(client, 'get_indicators', return_value=INDICATOR_LIST)
    res = fetch_indicators(client, update_context=False)
    assert len(res) == 1


@pytest.mark.parametrize('command', ['test-module', 'threat-intelligence-get-indicators'])
def test_main(mocker, command):
    from ThreatIntelligence import main, MandiantClient
    import demistomock as demisto

    params = {'auth': {'identifier': 'identifier', 'password': 'password'},
              'insecure': True,
              'url': 'url',
              'first_fetch': "89 days ago",
              'indicatorMetadata': True,
              'limit': 10,
              'indicatorRelationships': True,
              'type': []}
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(MandiantClient, '_retrieve_token', return_value='token')
    mocker.patch.object(demisto, 'command', return_value=command)
    main()


def test_get_indicators_by_value(mocker):
    """
        Given -
           client
        When -
            getting new indicators
        Then -
            receive list of indicators
    """
    client = mock_client()

    raw_indicator_post = {
        "indicators": [
            {
                "id": "fqdn--some-uuid-goes-here",
                "mscore": 50,
                "type": "fqdn",
                "value": "msdns.example.com",
                "is_exclusive": True,
                "is_publishable": True,
                "sources": [
                ],
                "attributed_associations": [
                ],
                "last_updated": "2022-08-16T04:52:49.046Z",
                "first_seen": "2011-09-12T12:23:13.000Z",
                "last_seen": "2022-07-18T23:15:03.000Z"
            }
        ]
    }

    mocker.patch.object(client, '_http_request', return_value=raw_indicator_post)
    res = client.get_indicators_by_value('msdns.example.com')

    assert res == [{'attributed_associations': [],
                    'first_seen': '2011-09-12T12:23:13.000Z',
                    'id': 'fqdn--some-uuid-goes-here',
                    'is_exclusive': True,
                    'is_publishable': True,
                    'last_seen': '2022-07-18T23:15:03.000Z',
                    'last_updated': '2022-08-16T04:52:49.046Z',
                    'mscore': 50,
                    'sources': [],
                    'type': 'fqdn',
                    'value': 'msdns.example.com'}]


def test_get_indicator_list():
    """
        Given -
           client
        When -
            getting new indicators
        Then -
            receive list of indicators
    """
    import ThreatIntelligence

    client = mock_client()
    res_indicators = util_load_json('./test_data/result_indicators.json')

    def get_new_indicators_mock(a, b, c, d):
        return res_indicators['new_indicators']

    ThreatIntelligence.get_new_indicators = get_new_indicators_mock
    res = ThreatIntelligence.get_indicator_list(client, 2, '90 days ago', 'Indicators')
    assert res == res_indicators['new_indicators']


def test_get_cvss_v3_score():
    example_cve = {
        "common_vulnerability_scores": {
            "v3.1": {
                "base_score": "V3.1Score"
            },
            "v2.0": {
                "base_score": "V2Score"
            }
        }
    }

    import ThreatIntelligence

    assert ThreatIntelligence.get_cvss_score(example_cve) == "V3.1Score"


def test_get_cvss_v2_score():
    example_cve = {
        "common_vulnerability_scores": {
            "v2.0": {
                "base_score": "V2Score"
            }
        }
    }

    import ThreatIntelligence

    assert ThreatIntelligence.get_cvss_score(example_cve) == "V2Score"


@pytest.mark.parametrize('value, type, response', [
    ('8.8.8.8', Common.IP, {
        "id": "ipv4--ae71927b-78e2-5659-8576-af0dc232b3e9",
        "mscore": 0,
        "type": "ipv4",
        "value": "8.8.8.8",
        "is_publishable": True,
        "sources": [
        ],
        "last_updated": "2022-10-25T15:01:24.711Z",
        "first_seen": "2014-09-01T21:39:51.000Z",
        "last_seen": "2022-10-25T15:01:21.000Z"
    }),
    ('google.com', Common.Domain, {
        "id": "fqdn--7baea406-cc1b-53f9-b1b2-ea4ad2f56dc1",
        "mscore": 0,
        "type": "fqdn",
        "value": "google.com",
        "is_publishable": True,
        "sources": [],
        "last_updated": "2022-10-25T17:03:58.528Z",
        "first_seen": "2014-09-01T21:39:23.000Z",
        "last_seen": "2022-10-25T16:51:58.000Z"
    }),
    ("fe09cf6d3a358305f8c2f687b6f6da02", Common.File, {
        "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
        "mscore": 100,
        "type": "md5",
        "value": "fe09cf6d3a358305f8c2f687b6f6da02",
        "is_exclusive": False,
        "is_publishable": True,
        "sources": [
        ],
        "associated_hashes": [
            {
                "id": "md5--e54a4f18-5d4d-56cd-8a41-a96938e9779f",
                "type": "md5",
                "value": "fe09cf6d3a358305f8c2f687b6f6da02"
            },
            {
                "id": "sha1--ad083435-4612-5b45-811a-157a77f65bdf",
                "type": "sha1",
                "value": "30d64987a6903a9995ea74fe268689811b14b81b"
            },
            {
                "id": "sha256--c17aca6a-7a35-5265-93f6-f6b5537cef7e",
                "type": "sha256",
                "value": "af95c55f3d09ee6c691afc248e8d4a9c07d4f304449c6f609bf9c4e4c202b070"
            }
        ],
        "attributed_associations": [
        ],
        "last_updated": "2022-10-19T00:37:24.612Z",
        "first_seen": "2022-01-13T23:01:27.000Z",
        "last_seen": "2022-08-12T22:05:41.000Z"
    }),
    ("https://google.com", Common.URL, {
        "id": "url--431bfcd3-a8a5-5103-9ad7-ac7f05891875",
        "mscore": 0,
        "type": "url",
        "value": "https://google.com",
        "is_publishable": True,
        "sources": [
        ],
        "last_updated": "2022-10-19T22:16:54.141Z",
        "first_seen": "2021-06-19T09:13:28.000Z",
        "last_seen": "2022-10-19T22:16:52.000Z"
    })
])
def test_fetch_by_value(mocker, value, type, response):
    import ThreatIntelligence
    raw_response = {"indicators": [response]}

    client = mock_client()

    mocker.patch.object(client, '_http_request', return_value=raw_response)
    res = ThreatIntelligence.fetch_indicator_by_value(client, {'indicator_value': value})

    assert isinstance(res.indicators[0], type)
import json
import io
import freezegun
import pytest
from FeedMandiant import MandiantClient


def mock_client():
    MandiantClient._get_token = lambda x: 'token'
    client = MandiantClient('url', 'username', 'password', False, False, 60, '90 days', 1, ['Malware'])
    return client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_generate_token(mocker):
    """
        Given -
           client
        When -
            generating a token
        Then -
            Validate the result is as expected
    """
    client = mock_client()

    mocker.patch.object(client, '_http_request', return_value={'access_token': 'token'})
    res = client._generate_token()
    assert res == 'token'


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
    from FeedMandiant import MandiantClient
    MandiantClient._generate_token = lambda x: 'token'
    client = MandiantClient('url', 'username', 'password', False, False, 60, 'x_app_name', 'first_fetch', 1, [])
    res = client._get_token()
    assert res == 'token'


@pytest.mark.parametrize('info_type, response, result',
                         [('info-type', {'info-type': 'res'}, 'res'),
                          ('', {'info-type': 'res'}, {'info-type': 'res'}),
                          ('attack-pattern', {'attack-patterns': 'redacted'}, []),
                          ('attack-pattern', {'attack-patterns': 'res'}, 'res')])
def test_get_indicator_additional_info(mocker, info_type, response, result):
    client = mock_client()
    mocker.patch.object(client, '_http_request', return_value=response)
    res = client.get_indicator_additional_info('identifier', 'Malware', info_type)
    assert res == result


def test_get_indicators_valid(mocker):
    client = mock_client()
    mocker.patch.object(client, '_http_request', return_value={'malware': ['list']})
    res = client.get_indicators('Malware')
    assert res == ['list']


def test_get_indicators_invalid(mocker):
    from FeedMandiant import DemistoException
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
    from FeedMandiant import get_new_indicators
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
    from FeedMandiant import get_verdict
    assert get_verdict(mscore) == res


def test_get_indicator_relationships():
    from FeedMandiant import get_indicator_relationships, EntityRelationship
    res = get_indicator_relationships({'field_indicator': [{'entity_b_field': 'value_b'}],
                                       'entity_a_field': 'value_a'}, 'field_indicator',
                                      'entity_a_field', 'entity_a_type', 'entity_b_field', 'entity_b_type',
                                      EntityRelationship.Relationships.RELATED_TO,
                                      EntityRelationship.Relationships.RELATED_TO)
    assert len(res) == 1
    assert res[0]._entity_a == 'value_a'
    assert res[0]._entity_a_type == 'entity_a_type'
    assert res[0]._entity_b == 'value_b'
    assert res[0]._entity_b_type == 'entity_b_type'
    assert res[0]._name == 'related-to'
    assert res[0]._reverse_name == 'related-to'


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
    'motivations': 'primarymotivation',
    'locations': {'target': [{'name': 'target'}]}

}


def test_create_malware_indicator():
    from FeedMandiant import create_malware_indicator
    client = mock_client()
    res = create_malware_indicator(client, BASIC_INDICATOR)
    assert res['value'] == 'name'
    assert res['type'] == 'Malware'
    assert len(res['fields']) == 11


def test_create_actor_indicator():
    from FeedMandiant import create_actor_indicator
    client = mock_client()
    res = create_actor_indicator(client, BASIC_INDICATOR)
    assert res['value'] == 'name'
    assert res['type'] == 'Threat Actor'
    assert len(res['fields']) == 7


@freezegun.freeze_time('2020-11-25T11:57:28Z')
def test_fetch_indicators(mocker):
    from FeedMandiant import fetch_indicators
    client = mock_client()
    mocker.patch.object(client, 'get_indicators', return_value=INDICATOR_LIST)
    res = fetch_indicators(client, update_context=False)
    assert len(res) == 1


@pytest.mark.parametrize('command', ['test-module', 'feed-mandiant-get-indicators'])
def test_main(mocker, command):
    from FeedMandiant import main, MandiantClient
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
    mocker.patch.object(MandiantClient, '_generate_token', return_value='token')
    mocker.patch.object(demisto, 'command', return_value=command)
    main()


def test_get_indicator_list():
    """
        Given -
           client
        When -
            getting new indicators
        Then -
            receive list of indicators
    """
    import FeedMandiant

    client = mock_client()
    res_indicators = util_load_json('./test_data/result_indicators.json')

    def get_new_indicators_mock(a, b, c, d):
        return res_indicators['new_indicators']

    FeedMandiant.get_new_indicators = get_new_indicators_mock
    res = FeedMandiant.get_indicator_list(client, 2, '90 days ago', 'Indicators')
    assert res == res_indicators['new_indicators']

import json
import io
import freezegun
import pytest
from FeedMandiant import MandiantClient


def mock_client():
    MandiantClient._get_token = lambda x: 'token'
    client = MandiantClient('url', 'username', 'password', False, False, 60, 'x_app_name', 'first_fetch', 1, [])
    return client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_create_indicator():
    """
        Given -
           raw indicator

        When -
            running create_indicator
        Then -
            Validate the result is as expected
    """
    from FeedMandiant import create_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    result_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_indicator(mock_client(), raw_indicators['metadata_indicator'])

    assert res == result_indicators['metadata_indicator']


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


@freezegun.freeze_time('2020-11-25T11:57:28Z')
def test_get_new_indicators(mocker):
    """
        Given -
           client
        When -
            getting new indicators
        Then -
            receive list of indicators
    """
    from FeedMandiant import get_new_indicators
    client = mock_client()

    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')

    mocker.patch.object(client, '_http_request', return_value=raw_indicators['new_indicators'])

    new_indicators = get_new_indicators(client, 'now', 'Indicators', 100)

    assert new_indicators == res_indicators['new_indicators']


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


def test_get_relationships_malware():
    from FeedMandiant import get_relationships_malware
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')

    res = get_relationships_malware(raw_indicators['metadata_indicator'])
    assert res == res_indicators['relationships_malware']


def test_get_relationships_actor():
    from FeedMandiant import get_relationships_actor
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')

    res = get_relationships_actor(raw_indicators['metadata_indicator'])
    assert res == res_indicators['relationships_actor']


def test_create_malware_indicator():
    from FeedMandiant import create_malware_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_malware_indicator(mock_client(), raw_indicators['metadata_indicator'])
    assert res == res_indicators['malware_indicator']


def test_create_report_indicator():
    from FeedMandiant import create_report_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_report_indicator(mock_client(), raw_indicators['metadata_indicator'], 'entity_a', 'entity_a_type')
    assert res == res_indicators['report_indicator']


def test_create_general_indicator():
    from FeedMandiant import create_general_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_general_indicator(raw_indicators['metadata_indicator'], 'entity_a', 'entity_a_type')
    assert res == res_indicators['general_indicator']


def test_create_attack_pattern_indicator():
    from FeedMandiant import create_attack_pattern_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_attack_pattern_indicator(mock_client(), raw_indicators['metadata_indicator'], 'entity_a', 'entity_a_type')
    assert res == res_indicators['attack_pattern_indicator']


def test_create_actor_indicator():
    from FeedMandiant import create_actor_indicator
    raw_indicators = util_load_json('./test_data/raw_indicators.json')
    res_indicators = util_load_json('./test_data/result_indicators.json')
    res = create_actor_indicator(mock_client(), raw_indicators['metadata_indicator'])
    assert res == res_indicators['actor_indicator']


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
    assert 1 == 1

import CategorizedFeeds
import demistomock as demisto
from unittest.mock import call


MOCK_INDICATORS = [
    {
        'attributes': {
            'md5': 'md5_random',
            'sha1': 'sha1_random',
            'sha256': 'sha256_random',
            'type_description': 'random_type',
        },
        'type': 'file',
        'id': 'sha256_random',
    },
    {
        'attributes': {
            'md5': 'md5_random2',
            'sha1': 'sha1_random2',
            'sha256': 'sha256_random2',
            'type_description': 'random_type2',
        },
        'type': 'file',
        'id': 'sha256_random2',
    }
]


def test_fetch_indicators_command(mocker):
    client = CategorizedFeeds.Client('https://fake')
    mocker.patch.object(client, 'fetch_indicators', return_value=None)
    mocker.patch.object(CategorizedFeeds, '_get_indicators', return_value=MOCK_INDICATORS)

    demisto.setIntegrationContext({})
    indicators = CategorizedFeeds.fetch_indicators_command(client, 'apt', [], limit=10)

    assert len(indicators) == 2
    assert indicators[0]['fields']['sha256'] == 'sha256_random'
    assert indicators[0]['sha256'] == 'sha256_random'
    assert indicators[0]['fileType'] == 'random_type'
    assert indicators[1]['fields']['sha256'] == 'sha256_random2'
    assert indicators[1]['sha256'] == 'sha256_random2'
    assert indicators[1]['fileType'] == 'random_type2'


def test_fetch_indicators_limit_command(mocker):
    client = CategorizedFeeds.Client('https://fake')
    mocker.patch.object(client, 'fetch_indicators', return_value=None)
    mocker.patch.object(CategorizedFeeds, '_get_indicators', return_value=MOCK_INDICATORS)

    demisto.setIntegrationContext({})
    indicators = CategorizedFeeds.fetch_indicators_command(client, 'apt', [], limit=1)

    assert len(indicators) == 1
    assert indicators[0]['fields']['sha256'] == 'sha256_random'
    assert indicators[0]['sha256'] == 'sha256_random'
    assert indicators[0]['fileType'] == 'random_type'


def test_main_manual_command(mocker):
    params = {
        'feed_type': 'apt',
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='gti-feed-get-indicators')
    get_feed_mock = mocker.patch.object(CategorizedFeeds.Client, 'get_threat_feed')

    CategorizedFeeds.main()

    assert get_feed_mock.call_args == call('apt')


def test_main_default_command(mocker):
    params = {
        'feed_type': 'iot',
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
        'limit': 10,
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    get_feed_mock = mocker.patch.object(CategorizedFeeds.Client, 'get_threat_feed')

    CategorizedFeeds.main()

    assert get_feed_mock.call_args == call('iot')


def test_main_test_command(mocker):
    params = {
        'credentials': {'password': 'xxx'},
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    get_feed_mock = mocker.patch.object(CategorizedFeeds.Client, 'fetch_indicators')

    CategorizedFeeds.main()

    assert get_feed_mock.call_count == 1

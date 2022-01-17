import pytest
import requests_mock

from FeedOffice365 import Client, get_indicators_command, fetch_indicators_command, build_region_list, ALL_REGIONS_LIST
from test_data.feed_data import RESPONSE_DATA


def test_fetch_indicators_command():
    with requests_mock.Mocker() as mock:
        url_dict = {
            "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
            "Region": 'Worldwide',
            "Service": 'Any'
        }
        mock.get(url_dict.get('FeedURL'), json=RESPONSE_DATA)
        client = Client([url_dict])
        indicators = fetch_indicators_command(client)
        assert len(indicators) == 10


@pytest.mark.parametrize('command, args, response, length', [
    (get_indicators_command, {'limit': 2, 'indicator_type': 'IPs'}, RESPONSE_DATA, 4),
    (get_indicators_command, {'limit': 2, 'indicator_type': 'URLs'}, RESPONSE_DATA, 6),
    (get_indicators_command, {'limit': 3, 'indicator_type': 'Both'}, RESPONSE_DATA, 10)
])  # noqa: E124
def test_commands(command, args, response, length, mocker):
    url_dict = {
        "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
        "Region": 'Worldwide',
        "Service": 'Any'
    }
    client = Client(urls_list=[url_dict], insecure=False)
    mocker.patch.object(client, 'build_iterator', return_value=response)
    human_readable, indicators_ec, raw_json = command(client, args)
    indicators = raw_json.get('raw_response')
    assert len(indicators) == length
    for indicator_json in indicators:
        indicator_val = indicator_json.get('value')
        indicator_type = indicator_json.get('type')
        assert indicator_val
        if indicator_type == 'Domain':
            assert args.get('indicator_type') != 'IPs'
        elif indicator_type == 'DomainGlob':
            assert args.get('indicator_type') != 'IPs'
        else:  # ip
            assert args.get('indicator_type') != 'URLs'


class TestFeedTags:
    urls = [{
        "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
        "Region": 'Worldwide',
        "Service": 'Any'
    }]

    @pytest.mark.parametrize('tags', [['tag1', 'tag2'], []])
    def test_feed_tags(self, mocker, tags):
        """
        Given:
        - tags parameters
        When:
        - Executing any command on feed
        Then:
        - Validate the tags supplied exists in the indicators
        """
        client = Client(self.urls, False, tags)
        mocker.patch.object(client, 'build_iterator', return_value=RESPONSE_DATA)
        _, _, raw_json = get_indicators_command(client, {'limit': 2, 'indicator_type': 'IPs'})
        assert tags == raw_json.get('raw_response')[0]['fields']['tags']


@pytest.mark.parametrize('config_region_list, response', [
    (['All'], ALL_REGIONS_LIST),
    (['All', 'my_region'], ALL_REGIONS_LIST + ['my_region']),
    (['my_region'], ['my_region'])
])  # noqa: E124
def test_build_region_list(config_region_list, response):
    """
    Given:
    - region lists provided by configurations
    When:
    - building the region list with build_region_list()
    Then:
    - Formatted region list will be returned:
        in cases 'All' item is in the config list,
        the returned region list will include 'ALL_REGIONS_LIST', and 'All' will be removed.
    """
    region_list = build_region_list(config_region_list)
    region_list.sort()
    response.sort()
    assert region_list == response

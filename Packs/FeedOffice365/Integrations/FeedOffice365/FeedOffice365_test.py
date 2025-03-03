import pytest
import requests_mock
import requests
import unittest
from unittest.mock import MagicMock, patch

from FeedOffice365 import Client, get_indicators_command, fetch_indicators_command, build_region_or_category_list, \
    ALL_REGIONS_LIST, ALL_CATEGORY_LIST
from test_data.feed_data import RESPONSE_DATA


@pytest.mark.parametrize('category_list, expected_indicators', [
    (ALL_CATEGORY_LIST, 10),
    (['Optimize'], 6),
    (['Allow'], 0)
])
def test_fetch_indicators_command(category_list, expected_indicators):
    """
    Given:
    - Global feed url and category list.
    (A) - Full category list.
    (B) - Category list containing only Optimize.
    (C) - Category list containing only Allow.

    When:
     - Fetching incidents.

    Then:
     - Ensure that the incidents returned are as expected.
     (A) - all incidents from response are handled and returned.
     (B) - only incidents with 'Optimize' category are returned.
    (C) - Empty list as there aren't any indicators with 'Allow' category.
    """
    with requests_mock.Mocker() as mock:
        url_dict = {
            "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
            "Region": 'Worldwide',
            "Service": 'Any'
        }
        mock.get(url_dict.get('FeedURL'), json=RESPONSE_DATA)
        client = Client([url_dict], category_list)
        indicators = fetch_indicators_command(client)
        assert len(indicators) == expected_indicators


def test_fetch_indicators_command__exclude_enrichment():
    """
    Given:
        - Exclude enrichment parameter is used
    When:
        - Calling the fetch_indicators_command
    Then:
        - The indicators should include the enrichmentExcluded field if exclude is True.
    """
    with requests_mock.Mocker() as mock:
        url_dict = {
            "FeedURL": 'https://endpoints.office.com/endpoints/worldwide',
            "Region": 'Worldwide',
            "Service": 'Any'
        }
        mock.get(url_dict.get('FeedURL'), json=RESPONSE_DATA)
        client = Client([url_dict], ALL_CATEGORY_LIST)
        indicators = fetch_indicators_command(client, enrichment_excluded=True)
        for ind in indicators:
            assert ind['enrichmentExcluded']


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
    client = Client(urls_list=[url_dict], category_list=ALL_CATEGORY_LIST, insecure=False)
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
        client = Client(self.urls, ALL_CATEGORY_LIST, False, tags)
        mocker.patch.object(client, 'build_iterator', return_value=RESPONSE_DATA)
        _, _, raw_json = get_indicators_command(client, {'limit': 2, 'indicator_type': 'IPs'})
        assert tags == raw_json.get('raw_response')[0]['fields']['tags']


@pytest.mark.parametrize('param_list, all_config_list, response', [
    (['All'], ALL_REGIONS_LIST, ALL_REGIONS_LIST),
    (['All', 'my_region'], ALL_REGIONS_LIST, ALL_REGIONS_LIST + ['my_region']),
    (['my_region'], ALL_REGIONS_LIST, ['my_region']),
    (['All'], ALL_CATEGORY_LIST, ALL_CATEGORY_LIST),
    (['All', 'Optimize', 'my_category'], ALL_CATEGORY_LIST, ALL_CATEGORY_LIST + ['my_category']),
    (['my_category'], ALL_CATEGORY_LIST, ['my_category']),
])  # noqa: E124
def test_build_region_or_category_list(param_list, all_config_list, response):
    """
    Given:
    - region or category lists provided by configurations
    When:
    - building the region or category list with build_region_or_category_list()
    Then:
    - Formatted list will be returned:
        in cases 'All' item is in the config list,
        the returned list will include all_config_list, and 'All' will be removed.
    """
    region_list = build_region_or_category_list(param_list, all_config_list)
    region_list.sort()
    response.sort()
    assert region_list == response


class TestClient(unittest.TestCase):

    def test_build_iterator_success(self):
        # Mock the requests library to return a successful response
        mock_response = MagicMock()
        mock_response.json.return_value = [{'ips': ['1.1.1.1'], 'category': 'category1'}]
        mock_get = MagicMock(return_value=mock_response)
        with patch('requests.get', mock_get):
            urls_list = [{'FeedURL': 'http://example.com', 'Region': 'Region1', 'Service': 'Service1'}]
            category_list = ['category1']
            client = Client(urls_list, category_list)
            result = client.build_iterator()
            assert result == [{'ips': ['1.1.1.1'], 'category': 'category1',
                               'Region': 'Region1', 'Service': 'Service1', 'FeedURL': 'http://example.com'}]

    def test_build_iterator_connection_error(self):
        # Mock the requests library to raise a ConnectionError
        mock_get = MagicMock(side_effect=requests.ConnectionError)
        with patch('requests.get', mock_get):
            urls_list = [{'FeedURL': 'http://example.com', 'Region': 'Region1', 'Service': 'Service1'}]
            category_list = ['category1']
            client = Client(urls_list, category_list)
            with self.assertRaises(Exception):
                client.build_iterator()

    def test_build_iterator_http_error(self):
        # Mock the requests library to raise an HTTPError
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_get = MagicMock(side_effect=requests.exceptions.HTTPError(response=mock_response))
        with patch('requests.get', mock_get):
            urls_list = [{'FeedURL': 'http://example.com', 'Region': 'Region1', 'Service': 'Service1'}]
            category_list = ['category1']
            client = Client(urls_list, category_list)
            with self.assertRaises(Exception):
                client.build_iterator()

    def test_build_iterator_value_error(self):
        # Mock the requests library to return an invalid JSON response
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError
        mock_get = MagicMock(return_value=mock_response)
        with patch('requests.get', mock_get):
            urls_list = [{'FeedURL': 'http://example.com', 'Region': 'Region1', 'Service': 'Service1'}]
            category_list = ['category1']
            client = Client(urls_list, category_list)
            with self.assertRaises(ValueError):
                client.build_iterator()

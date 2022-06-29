import pytest
from FeedAutofocusDaily import Client, fetch_indicators_command, get_indicators_command

from CommonServerPython import *


INDICATORS = [
    "d4da1b2d5554587136f2bcbdf0a6a1e29ab83f1d64a4b2049f9787479ad02fad",
    "19.117.63.253",
    "19.117.63.253:8080",
    "domaintools.com",
    "flake8.pycqa.org/en/latest",
    "19.117.63.253/28",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348/32",
    "19.117.63.253:28/other/path"
]

TYPES = [
    "File",
    "IP",
    "IP",
    "Domain",
    "URL",
    "CIDR",
    "IPv6",
    "IPv6CIDR",
    "URL"
]


@pytest.fixture()
def auto_focus_client():
    return Client(api_key="a", insecure=False)


def test_fetch_indicators_command(mocker, auto_focus_client):
    mocker.patch.object(auto_focus_client, 'daily_http_request', return_value=INDICATORS)
    indicators = fetch_indicators_command(auto_focus_client, 9, 0)
    for i in range(0, 9):
        assert indicators[i]['type'] == TYPES[i]


@pytest.mark.parametrize('tlp_color', ['', None, 'AMBER'])
def test_feed_tags_param(mocker, auto_focus_client, tlp_color):
    """Unit test
    Given
    - fetch indicators command
    - command args
    - command raw response
    When
    - mock the feed tags param.
    - mock the Client's daily_http_request.
    Then
    - run the fetch incidents command using the Client
    Validate The value of the tags field.
    """
    mocker.patch.object(auto_focus_client, 'daily_http_request', return_value=INDICATORS)
    indicators = fetch_indicators_command(auto_focus_client, ['test_tag'], tlp_color)
    assert indicators[0].get('fields').get('tags') == ['test_tag']
    if tlp_color:
        assert indicators[0].get('fields').get('trafficlightprotocol') == tlp_color
    else:
        assert not indicators[0].get('fields').get('trafficlightprotocol')


INDICATORS_CLASSIFICATION_DATA = [
    (
        "1.1.1.1/path", FeedIndicatorType.URL
    ),
    (
        "1.1.1.1:8080", FeedIndicatorType.IP
    ),
    (
        "19.117.63.253:28/other/path", FeedIndicatorType.URL
    ),
    (
        "19.117.63.253:28/path", FeedIndicatorType.URL
    ),
    (
        '1.1.1.1/7', FeedIndicatorType.CIDR
    ),
    (
        "1.1.1.1/7/server/somestring/something.php?fjjasjkfhsjasofds=sjhfhdsfhasld", FeedIndicatorType.URL
    ),
    (
        "1.1.1.1/7/server", FeedIndicatorType.URL
    ),
    (
        "d4da1b2d5554587136f2bcbdf0a6a1e29ab83f1d64a4b2049f9787479ad02fad", FeedIndicatorType.File
    ),
    (
        "domaintools.com", FeedIndicatorType.Domain
    ),
    (
        "test.test.com", FeedIndicatorType.Domain
    ),
    (
        "flake8.pycqa.org/en/latest", FeedIndicatorType.URL
    ),
    (
        "19.117.63.253/28", FeedIndicatorType.CIDR,
    ),
    (
        "2001:db8:85a3:8d3:1319:8a2e:370:7348", FeedIndicatorType.IPv6
    ),
    (
        "2001:db8:85a3:8d3:1319:8a2e:370:7348/path/path", FeedIndicatorType.URL
    ),
    (
        "2001:db8:85a3:8d3:1319:8a2e:370:7348/32", FeedIndicatorType.IPv6CIDR
    ),
    (
        "2001:db8:85a3:8d3:1319:8a2e:370:7348/path", FeedIndicatorType.URL
    ),
    (
        "2001:db8:85a3:8d3:1319:8a2e:370:7348/32/path", FeedIndicatorType.URL
    )
]


@pytest.mark.parametrize('indicator, expected_indicator_type', INDICATORS_CLASSIFICATION_DATA)
def test_indicator_classified_to_the_correct_type(mocker, auto_focus_client, indicator, expected_indicator_type):
    """
    Given
    - an indicator as string.

    When
    - trying to find the indicator type.

    Then
    - the indicator is classified correctly.
    """
    mocker.patch.object(auto_focus_client, 'daily_http_request')
    assert auto_focus_client.find_indicator_type(indicator=indicator) == expected_indicator_type


LIMIT_AND_OFFSET = [(0, 2), (0, 3), (0, 4), [1, 4], [3, 2], [4, 5]]


@pytest.mark.parametrize('offset, limit', LIMIT_AND_OFFSET)
def test_fetch_indicators_filtered_correctly(mocker, auto_focus_client, offset, limit):
    """
    Given
    - a limit and an offset

    When
    - fetching indicators

    Then
    - The indicator response is filtered correctly.
    """
    mocker.patch.object(auto_focus_client, 'daily_http_request', return_value=INDICATORS)
    indicators = fetch_indicators_command(auto_focus_client, feed_tags=[], tlp_color=None, limit=limit, offset=offset)
    assert len(indicators) == limit

    indicator_types = [indicator['type'] for indicator in indicators]
    assert indicator_types == TYPES[offset: offset + limit]


def test_get_indicators_command(mocker, auto_focus_client):
    """
    Given
    - indicators list

    When
    - getting all the indicators

    Then
    - make sure the indicator type and values are returned correctly.
    """
    mocker.patch.object(auto_focus_client, 'daily_http_request', return_value=INDICATORS)
    _, _, indicators = get_indicators_command(auto_focus_client, {}, feed_tags=[], tlp_color=None)
    for i in range(0, 9):
        assert indicators[i]['type'] == TYPES[i]
        assert indicators[i]['value'] in INDICATORS[i]

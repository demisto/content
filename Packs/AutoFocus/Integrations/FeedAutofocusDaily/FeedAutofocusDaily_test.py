from FeedAutofocusDaily import Client, fetch_indicators_command

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


def test_fetch_indicators_command(mocker):
    client = Client(api_key="a", insecure=False)
    mocker.patch.object(client, 'daily_http_request', return_value=INDICATORS)
    indicators = fetch_indicators_command(client, 9, 0)
    for i in range(0, 9):
        assert indicators[i]['type'] == TYPES[i]


def test_type_finder():
    client = Client(api_key="a", insecure=False)
    for i in range(0, 9):
        indicator_type = client.find_indicator_type(INDICATORS[i])
        assert indicator_type == TYPES[i]


def test_feed_tags_param(mocker):
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
    client = Client(api_key="a", insecure=False)
    mocker.patch.object(client, 'daily_http_request', return_value=INDICATORS)
    indicators = fetch_indicators_command(client, ['test_tag'])
    assert indicators[0].get('fields').get('tags') == ['test_tag']

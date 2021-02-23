from FeedHelloWorld import Client


URL = "https://openphish.com/feed.txt"


def test_build_iterator(requests_mock):
    """

    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response

    """
    with open('test_data/FeedHelloWorld_mock.txt', 'r') as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_url = 'http://wagrouphot2021.ddns.net/'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    url_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'URL'}
    assert expected_url in url_indicators

 def test_fetch_indicators():
    """

    Given:
        - Output of the feed API as list
    When:
        - Fetching indicators from the API
    Then:
        - Create indicator objects list

    """
    mocker.patch.object(Client, "build_iterator", return_value=util_load_json('./build_iterator_results')
    results = fetch_indicators_command(client, limit=limit)
#
#
# def test_get_indicators_command()

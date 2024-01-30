import json
import io
import GreyNoiseIndicator as feed


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_indicators(requests_mock, mocker):
    """Tests the fetch-indicators command function.

    Configures requests_mock instance to generate the appropriate
    get_indicator API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from GreyNoiseIndicator import Client, fetch_indicators

    mock_indicators_response = util_load_json('test_data/search_indicators.json')
    requests_mock.get(
        'https://api.greynoise.io/v2/experimental/gnql?query=last_seen%3A1d&size=1',
        json=mock_indicators_response)

    client = Client(api_key='apikey')

    mocker.patch.object(client)

    assert fetch_indicators(
        client=client,
        params=params
    )

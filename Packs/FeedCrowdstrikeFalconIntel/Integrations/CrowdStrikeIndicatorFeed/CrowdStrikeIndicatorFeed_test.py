import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_crowdstrike_indicators_list_command(requests_mock):
    """Tests crowdstrike_indicators_list_command function
        Given
            - The following indicator type: 'domain' that was chosen by the user.
            - include_deleted: False
        When
            - Calling `crowdstrike_indicators_list_command`
        Then
            - convert the result to indicators list
            - validate the length of the indicators list
        """

    from CrowdStrikeIndicatorFeed import Client, crowdstrike_indicators_list_command

    mock_response = util_load_json('test_data/crowdstrike_indicators_list_command.json')
    requests_mock.post('https://api.crowdstrike.com/oauth2/token', json={'access_token': '12345'})
    requests_mock.get(url='https://api.crowdstrike.com/intel/combined/indicators/v1', json=mock_response)

    client = Client(base_url='https://api.crowdstrike.com/', client_id='client_id', client_secret='client_secret')
    args = {
        'type': 'Domain',
        'include_deleted': 'false',
        'limit': '2'
    }
    response = crowdstrike_indicators_list_command(client, args)

    assert len(response.outputs) == 2
    assert len(response.raw_response) == 3
    assert "Indicators from CrowdStrike Falcon Intel" in response.readable_output

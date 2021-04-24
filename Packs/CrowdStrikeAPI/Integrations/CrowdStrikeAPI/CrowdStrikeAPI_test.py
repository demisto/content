import io
import json

import pytest

from CrowdStrikeAPI import Client, api_request


@pytest.fixture()
def client(requests_mock):
    requests_mock.post(
        'https://api.crowdstrike.com/oauth2/token',
        json={
            'access_token': 'access_token',
        },
    )
    return Client(params={})


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_api_request(client, requests_mock):
    """
    Given:
        - Query behaviors endpoint
    When:
        - Running api request command
    Then:
        - Verify request sent as expected
        - Verify command outputs are as expected
    """
    endpoint = '/incidents/queries/behaviors/v1'
    query_parameters = '{"limit":1}'
    args = {
        'endpoint': endpoint,
        'query_parameters': query_parameters,
    }
    api_response = util_load_json('./test_data/query_behaviors_response.json')
    requests_mock.get('https://api.crowdstrike.com' + endpoint + '?limit=1', json=api_response)

    result = api_request(client=client, args=args)

    assert result.outputs == api_response['resources']

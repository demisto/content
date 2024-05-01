import json

import pytest

from CrowdStrikeOpenAPI import Client, query_behaviors_command


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
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_query_behaviors(client, requests_mock):
    """
    Given:
        - Limit arg set to 1
    When:
        - Running query behaviors command
    Then:
        - Verify request sent as expected
        - Verify command outputs are as expected
    """
    args = {
        'limit': '1'
    }
    api_response = util_load_json('./test_data/query_behaviors_response.json')
    requests_mock.get('https://api.crowdstrike.com/incidents/queries/behaviors/v1?limit=1', json=api_response)

    result = query_behaviors_command(client=client, args=args)

    assert result.outputs == api_response

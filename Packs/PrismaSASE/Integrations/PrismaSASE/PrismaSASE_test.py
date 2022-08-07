
import json
import pytest

from PrismaSASE import Client


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        str: Mock file content.

    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"name": "cid-1252366",
          "folder": "Shared",
          "position": "pre",
          "action": "allow",
          "source_hip": "any",
          "destination_hip": "any",
          "from": "trust",
          "to": "trust",
          "source": "PA-GP-Mobile-User-Pool",
          "destination": "any",
          "source_user": "any",
          "category": "any",
          "application": "any",
          "service": "application-default",
          "log_setting": "Cortex Data Lake",
          "profile_setting": "best-practice",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_create_security_rule_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import create_security_rule_command
    mock_response = json.loads(load_mock_response('security-rule.json'))
    requests_mock.post('http://base_url/sse/config/v1/security-rules', json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')

    result = create_security_rule_command(client, args, default_tsg_id)

    assert result.outputs_prefix == 'PrismaAccess.CreatedSecurityRule'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"folder": "Shared",
          "position": "pre",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_list_security_rules_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import list_security_rules_command
    mock_response = json.loads(load_mock_response('list-security-rules.json'))
    requests_mock.get('http://base_url/sse/config/v1/security-rules?folder=Shared&position=pre', json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = list_security_rules_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.FoundSecurityRule'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"devices": "Mobile Users",
          "description": "Description",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_push_candidate_config_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import push_candidate_config_command
    mock_response = json.loads(load_mock_response('push-candidate-config.json'))
    requests_mock.post('http://base_url/sse/config/v1/config-versions/candidate:push', json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = push_candidate_config_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.ConfigPush'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"id": "1624ec11-b599-4372-a0d7-fec07ecb8203",
          "name": "cid-1252366",
          "folder": "Shared",
          "position": "pre",
          "action": "allow",
          "source_hip": "any",
          "destination_hip": "any",
          "from": "trust",
          "to": "untrust",
          "source": "PA-GP-Mobile-User-Pool",
          "destination": "any",
          "source_user": "any",
          "category": "any",
          "application": "any",
          "service": "application-default",
          "log_setting": "Cortex Data Lake",
          "profile_setting": "best-practice",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_update_security_rule_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import update_security_rule_command
    mock_response = json.loads(load_mock_response('update-security-rule.json'))
    mock_url = f'http://base_url/sse/config/v1/security-rules/{args.get("id")}?folder=Shared&position=pre'

    requests_mock.put(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = update_security_rule_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.UpdatedSecurityRule'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"uri": "/mt/monitor/v1/agg/alerts/list",
          "query_data": """{\"filter\": {
                  \"operator\": \"AND\",
                  \"rules\": [
                      {
                          \"operator\": \"in\",
                          \"property\": \"domain\",
                          \"values\": [
                              \"External\",
                              \"external\"
                          ]
                      },
                      {
                          \"operator\": \"last_n_days\",
                          \"property\": \"event_time\",
                          \"values\": [
                              7
                          ]
                      }
                  ]
              },
              \"properties\": [
                  {
                      \"property\": \"total_count\"
                  },
                  {
                      \"property\": \"mu_count\"
                  },
                  {
                      \"property\": \"rn_count\"
                  },
                  {
                      \"property\": \"sc_count\"
                  }
              ]
          }""", "tsg_id": "1234567"}, "1234567")
    ]
)
def test_query_agg_monitor_api_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import query_agg_monitor_api_command
    mock_response = json.loads(load_mock_response('query-agg-monitor-api.json'))
    mock_url = 'http://base_url/mt/monitor/v1/agg/alerts/list?agg_by=tenant'

    requests_mock.post(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = query_agg_monitor_api_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaSASE.AggregateQueryResponse'
    assert result.outputs == mock_response


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"name": "cid-1252366",
          "folder": "Shared",
          "position": "pre",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_get_security_rule_by_name_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import get_security_rule_by_name_command
    mock_response = json.loads(load_mock_response('get-security-rule-by-name.json'))
    mock_url = f'http://base_url/sse/config/v1/security-rules?folder=Shared&position=pre&name={args.get("name")}&limit=1&offset=0'

    requests_mock.get(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = get_security_rule_by_name_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.FoundSecurityRule'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"id": "294",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_get_config_jobs_by_id_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import get_config_jobs_by_id_command
    mock_response = json.loads(load_mock_response('get-config-jobs-by-id.json'))
    mock_url = f'http://base_url/sse/config/v1/jobs/{args.get("id")}'

    requests_mock.get(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = get_config_jobs_by_id_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.ConfigJob'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"limit": "2",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_list_config_jobs_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import list_config_jobs_command
    mock_response = json.loads(load_mock_response('list-config-jobs.json'))
    mock_url = 'http://base_url/sse/config/v1/jobs?limit=2'

    requests_mock.get(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = list_config_jobs_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.ConfigJob'
    assert result.outputs == mock_response.get('data')


@pytest.mark.parametrize(
    # Write and define the expected
    "args, default_tsg_id",
    [
        ({"rule_id": "b71e385c-1c8a-42fc-94e4-54bccbd148b9",
          "tsg_id": "1234567"}, "1234567")
    ]
)
def test_delete_security_rule_command(mocker, requests_mock, args, default_tsg_id):

    from PrismaSASE import delete_security_rule_command
    mock_response = json.loads(load_mock_response('security-rule.json'))
    mock_url = f'http://base_url/sse/config/v1/security-rules/{args.get("rule_id")}'

    requests_mock.delete(mock_url, json=mock_response)
    client = Client(base_url='http://base_url',
                    client_id='clientid',
                    client_secret='clientsecret',
                    oauth_url='oauthurl',
                    verify='false',
                    proxy='false')

    mocker.patch.object(client, 'get_access_token', return_value='access_token')
    result = delete_security_rule_command(client, args, default_tsg_id)
    assert result.outputs_prefix == 'PrismaAccess.DeletedSecurityRule'
    assert result.outputs == mock_response

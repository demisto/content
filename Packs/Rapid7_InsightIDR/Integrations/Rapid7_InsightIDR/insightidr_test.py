"""InsightIDR Integration for Cortex XSOAR - Unit Tests file"""
import io
import json
from CommonServerPython import *

REGION = 'us'


def util_load_json(path) -> dict:
    with io.open(path, mode='r', encoding='utf-8') as file:
        return json.loads(file.read())


def util_load_file(path) -> str:
    with io.open(path, mode='r', encoding='utf-8') as file:
        return file.read()


def test_insight_idr_list_investigations(requests_mock) -> None:
    """
        Tests insight_idr_list_investigations_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_list_investigations_command

    mock_response = util_load_json('test_data/list_investigations.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_list_investigations_command(client)

    outputs = []
    for investigation in response.raw_response.get('data', []):
        outputs.append(investigation)

    assert response.outputs_prefix == 'Rapid7InsightIDR.Investigation'
    assert response.outputs_key_field == 'id'
    assert response.outputs == outputs


def test_insight_idr_get_investigation(requests_mock) -> None:
    """
        Tests insight_idr_get_investigation_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_get_investigation_command

    mock_response = util_load_json('test_data/get_investigation.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )

    response = insight_idr_get_investigation_command(client, '174e4f99-2ac7-4481-9301-4d24c34baf06')

    assert response.outputs_prefix == 'Rapid7InsightIDR.Investigation'
    assert response.outputs_key_field == 'id'
    assert response.outputs == response.raw_response


def test_close_investigation(requests_mock) -> None:
    """
        Tests insight_idr_close_investigations_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_close_investigations_command

    mock_response = util_load_json('test_data/close_investigations.json')
    requests_mock.post(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations/bulk_close',
        json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )

    response = insight_idr_close_investigations_command(client, 'start_time', 'end_time', 'MANUAL')

    assert response.raw_response.get('num_closed', -1) == len(response.raw_response.get('ids', []))
    assert response.outputs_prefix == 'Rapid7InsightIDR.Investigation'
    assert response.outputs_key_field == 'id'


def test_assign_user(requests_mock) -> None:
    """
        Tests insight_idr_assign_user_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_assign_user_command

    investigation_id = '174e4f99-2ac7-4481-9301-4d24c34baf06'
    email = 'example@test.com'

    mock_response = util_load_json('test_data/assign_user.json')
    requests_mock.put(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations/'
        f'{investigation_id}/assignee', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )

    response = insight_idr_assign_user_command(client, investigation_id, email)
    if response.raw_response:
        for data in response.raw_response:
            for obj in data.get('data', []):
                assert obj.get('assignee', {}).get('email', '') == email

    assert response.outputs_prefix == 'Rapid7InsightIDR.Investigation'
    assert response.outputs_key_field == 'id'


def test_set_status(requests_mock) -> None:
    """
        Tests insight_idr_set_status_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_set_status_command

    investigation_id = '174e4f99-2ac7-4481-9301-4d24c34baf06'
    status = 'OPEN'

    mock_response = util_load_json('test_data/set_status.json')
    requests_mock.put(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations/{investigation_id}'
        f'/status/{status}', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )

    response = insight_idr_set_status_command(client, investigation_id, status)

    if response.raw_response:
        for data in response.raw_response:
            for obj in data.get('data', []):
                assert obj.get('status', '') == status

    assert response.outputs_prefix == 'Rapid7InsightIDR.Investigation'
    assert response.outputs_key_field == 'id'


def test_insight_idr_add_threat_indicators(requests_mock) -> None:
    """
        Tests insight_idr_add_threat_indicators_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_add_threat_indicators_command

    mock_response = util_load_json('test_data/add_threat_indicators.json')
    requests_mock.post(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/customthreats/key/x/indicators/add',
        json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_add_threat_indicators_command(client, 'x')

    outputs = []
    for threat in response.raw_response:
        outputs.append(threat.get('threat'))

    assert response.outputs_prefix == 'Rapid7InsightIDR.Threat'
    assert response.outputs_key_field == 'name'
    assert response.outputs == outputs


def test_insight_idr_replace_threat_indicators(requests_mock) -> None:
    """
        Tests insight_idr_replace_threat_indicators_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_replace_threat_indicators_command

    mock_response = util_load_json('test_data/replace_threat_indicators.json')
    requests_mock.post(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/customthreats/key/x/indicators/replace',
        json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_replace_threat_indicators_command(client, 'x')

    outputs = []
    for threat in response.raw_response:
        outputs.append(threat.get('threat'))

    assert response.outputs_prefix == 'Rapid7InsightIDR.Threat'
    assert response.outputs_key_field == 'name'
    assert response.outputs == outputs


def test_insight_idr_list_logs(requests_mock) -> None:
    """
        Tests insight_idr_list_logs_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_list_logs_command

    mock_response = util_load_json('test_data/list_logs.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/log_search/management/logs', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_list_logs_command(client)

    outputs = []
    for log in response.raw_response.get('logs', []):
        outputs.append(log)

    assert response.outputs_prefix == 'Rapid7InsightIDR.Log'
    assert response.outputs_key_field == 'id'
    assert response.outputs == outputs


def test_insight_idr_list_log_sets(requests_mock) -> None:
    """
        Tests insight_idr_list_log_sets_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_list_log_sets_command

    mock_response = util_load_json('test_data/list_log_sets.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/log_search/management/logsets',
        json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_list_log_sets_command(client)

    outputs = []
    for log in response.raw_response.get('logsets', []):
        outputs.append(log)

    assert response.outputs_prefix == 'Rapid7InsightIDR.LogSet'
    assert response.outputs_key_field == 'id'
    assert response.outputs == outputs


def test_insight_idr_download_logs(requests_mock) -> None:
    """
        Tests insight_idr_download_logs_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local TEXT file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_download_logs_command

    mock_response = util_load_file('test_data/download_logs.txt')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/log_search/download/logs/x:y', text=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_download_logs_command(client, 'x:y')

    assert (response.get('File', '')[-4:]) == '.log'


def test_insight_idr_query_log(requests_mock) -> None:
    """
        Tests insight_idr_query_log_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_query_log_command

    mock_response = util_load_json('test_data/list_log_sets.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/log_search/query/logs/x', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_query_log_command(client, 'x', '', '', '')

    outputs = []
    for event in response.raw_response.get('events', []):
        outputs.append(event)

    assert response.outputs_prefix == 'Rapid7InsightIDR.Event'
    assert response.outputs_key_field == 'message'
    assert response.outputs == outputs


def test_insight_idr_query_log_set(requests_mock) -> None:
    """
        Tests insight_idr_query_log_set_command.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, insight_idr_query_log_set_command

    mock_response = util_load_json('test_data/list_log_sets.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/log_search/query/logsets/x', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )
    response = insight_idr_query_log_set_command(client, 'x', '', '', '')

    outputs = []
    for event in response.raw_response.get('events', []):
        outputs.append(event)

    assert response.outputs_prefix == 'Rapid7InsightIDR.Event'
    assert response.outputs_key_field == 'message'
    assert response.outputs == outputs


def test_fetch_incidents(requests_mock) -> None:
    """
        Tests fetch_incidents.
        Configures requests_mock instance to generate the appropriate
        API response, loaded from a local JSON file. Checks
        the output of the command function with the expected output.
    """
    from insightidr import Client, fetch_incidents

    mock_response = util_load_json('test_data/list_investigations.json')
    requests_mock.get(
        f'https://{REGION}.api.insight.rapid7.com/idr/v1/investigations', json=mock_response)

    client = Client(
        base_url=f'https://{REGION}.api.insight.rapid7.com/',
        verify=False,
        headers={
            'Authentication': 'apikey'
        },
        proxy=False
    )

    last_fetch_timestamp = parse_date_range('1 day', to_timestamp=True)[0]
    last_run = {'last_fetch': last_fetch_timestamp}

    response = fetch_incidents(client=client,
                               max_fetch='1',
                               last_run=last_run,
                               first_fetch_time='1 day')
    outputs = []
    for investigation in response[1]:
        outputs.append(investigation)

    assert last_fetch_timestamp + 1 == response[0]['last_fetch']
    assert response[1] == [{
        'name': 'Joe enabled account Joebob',
        'occurred': '2018-06-06T16:56:42.000Z',
        'rawJSON': outputs[0]['rawJSON'],
    },
    {
        'name': 'Hello',
        'occurred': '2018-06-06T16:56:43.000Z',
        'rawJSON': outputs[1]['rawJSON'],
    }
    ]
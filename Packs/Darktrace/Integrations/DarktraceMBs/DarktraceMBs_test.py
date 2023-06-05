import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""*****COMMAND FUNCTIONS****"""


def test_get_model_breach(requests_mock):
    """Tests darktrace-get--model-breach command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, get_model_breach_command

    # GIVEN an integration is configured to Darktrace
    mock_api_response = util_load_json('test_data/get_breach.json')
    requests_mock.get('https://mock.darktrace.com/modelbreaches?pbid=95',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 95
    args = {
        'pbid': '95',
    }

    integration_response = get_model_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_get_breach.json')

    # THEN the response should be returned and formatted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, fetch_incidents

    # GIVEN an integration is configured and fetch incidents
    mock_response = util_load_json('test_data/fetch_breach.json')
    requests_mock.get('https://usw1-51965-01.cloud.darktrace.com/modelbreaches?minscore=0.0&starttime=1598932817000',
                      json=mock_response)

    client = Client(
        base_url='https://usw1-51965-01.cloud.darktrace.com/',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the most recent call was made on Mon, Aug 31, 2020 9 PM Pacific
    last_run = {
        'last_fetch': 1598932817000  # Mon, Aug 31, 2020 9 PM Pacific
    }

    _, integration_response = fetch_incidents(
        client=client,
        max_alerts=20,
        last_run=last_run,
        first_fetch_time='1 day ago',
        min_score=0
    )

    # THEN the relevant information will be fetched and pulled
    expected_response = util_load_json('test_data/formatted_fetch_breach.json')

    assert integration_response == expected_response
    assert len(integration_response) == 2


def test_get_model_breach_connections(mocker):
    """Tests the get-modelbreach-connections command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, get_model_breach_connections_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/breach_details.json')
    mocker.patch.object(Client, 'get_model_breach_connections', return_value=mock_api_response)
    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'pbid': '123',
        'count': '2',
        'endtime': 1629803362,
        'offset': 0
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_model_breach_connections_command(client, args)
    expected_response = util_load_json('test_data/formatted_breach_details.json')

    assert integration_response.outputs == expected_response
    assert len(mock_api_response) == len(expected_response) + 1
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'


def test_get_model(requests_mock):
    """Tests the get-model command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, get_model_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/model.json')
    requests_mock.get('https://mock.darktrace.com/models?uuid=80010119-6d7f-0000-0305-5e0000000325',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'uuid': '80010119-6d7f-0000-0305-5e0000000325'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_model_command(client, args)
    expected_response = util_load_json('test_data/formatted_model.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Model'


def test_get_model_component(requests_mock):
    """Tests the get-component command function.
    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, get_model_component_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/component.json')
    requests_mock.get('https://mock.darktrace.com/components?cid=254503',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'cid': '254503'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_model_component_command(client, args)
    expected_response = util_load_json('test_data/formatted_component.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Model.Component'


def test_get_model_breach_comments(requests_mock):
    """Tests darktrace-get-model-breach-comments command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, get_model_breach_comments_command

    # GIVEN an integration is configured and comments are desired
    mock_api_response = util_load_json('test_data/get_comments.json')
    requests_mock.get('https://mock.darktrace.com/mbcomments?pbid=2507',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 46
    args = {
        'pbid': '2507',
    }

    integration_response = get_model_breach_comments_command(client, args)
    expected_response = util_load_json('test_data/formatted_get_comments.json')

    # THEN the comments should be returned and formatted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach.Comment'


def test_acknowledge_model_breach(requests_mock):
    """Tests darktrace-acknowledge-model-breach command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, acknowledge_model_breach_command

    # GIVEN an integration is configured and you would like to acknowledge a breach
    mock_api_response = util_load_json('test_data/ack_success.json')
    requests_mock.post('https://mock.darktrace.com/modelbreaches/2509/acknowledge', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 111
    args = {
        'pbid': '2509',
    }

    integration_response = acknowledge_model_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_ack_success.json')

    # THEN the breach should be acknowledged, context updated, and message posted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'


def test_unacknowledge(requests_mock):
    """Tests darktrace-unacknowledge command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceMBs import Client, unacknowledge_model_breach_command

    # GIVEN an integration is configured and you would like to unacknowledge a breach
    mock_api_response = util_load_json('test_data/ack_success.json')
    requests_mock.post('https://mock.darktrace.com/modelbreaches/2509/unacknowledge', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 111
    args = {
        'pbid': '2509',
    }

    integration_response = unacknowledge_model_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_unack_success.json')

    # THEN the breach should be acknowledged, context updated, and message posted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'


def test_post_comment_to_model_breach(requests_mock):

    from DarktraceMBs import Client, post_comment_to_model_breach_command

    # GIVEN an integration is configured and you would like to unacknowledge a breach
    mock_api_response = util_load_json('test_data/comment_post.json')
    requests_mock.post('https://mock.darktrace.com/modelbreaches/2509/comments', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 111
    args = {
        'pbid': '2509',
        'message': 'Test comment post'
    }

    integration_response = post_comment_to_model_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_comment_post.json')

    # THEN the breach should be acknowledged, context updated, and message posted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'

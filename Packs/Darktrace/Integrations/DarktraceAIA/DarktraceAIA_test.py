import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


"""*****COMMAND FUNCTIONS****"""


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import Client, fetch_incidents

    # GIVEN an integration is configured and fetch incidents
    mock_response = util_load_json('test_data/incident_fetch.json')
    requests_mock.get('https://usw1-51965-01.cloud.darktrace.com/aianalyst/'
                      + 'incidentevents?mingroupscore=0&starttime=1598932817000',
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
    expected_response = util_load_json('test_data/formatted_incident_fetch.json')

    assert integration_response == expected_response
    assert len(integration_response) == 2


def test_get_ai_analyst_incident_event(requests_mock):
    """Tests get_ai_analyst_incident_event command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import Client, get_ai_analyst_incident_event_command

    # GIVEN an integration is configured and fetch incidents
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/ai_analyst_incident.json')
    requests_mock.get('https://mock.darktrace.com/aianalyst/incidentevents?uuid=' + eventId,
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
    }
    integration_response = get_ai_analyst_incident_event_command(client, args)
    expected_response = util_load_json('test_data/formatted_ai_analyst_incident.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'


def test_get_comments_for_ai_analyst_incident_event_command(requests_mock):
    """Tests get_comments_for_ai_analyst_incident_event_command command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import (
        Client, get_comments_for_ai_analyst_incident_event_command)

    # GIVEN an integration is configured and fetch incidents
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/get_comment_response.json')
    requests_mock.get('https://mock.darktrace.com/aianalyst/incident/comments?incident_id=' + eventId,
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
    }
    integration_response = get_comments_for_ai_analyst_incident_event_command(client, args)
    expected_response = util_load_json('test_data/formatted_get_comment_response.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'


def test_post_comment_to_ai_analyst_incident_event(requests_mock):
    """Tests post_comments_for_ai_analyst_incident_event_command command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import (
        Client, post_comment_to_ai_analyst_incident_event_command)

    # GIVEN an integration is configured and fetch incidents
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/post_comment.json')
    requests_mock.post('https://mock.darktrace.com/aianalyst/incident/comments',
                       json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
        'comment': "test comment"
    }
    integration_response = post_comment_to_ai_analyst_incident_event_command(client, args)
    expected_response = util_load_json('test_data/formatted_post_comment.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'


def test_acknowledge_ai_analyst_incident_event(requests_mock):
    """Tests acknowledge_ai_analyst_incident_event_command command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import (Client,
                              acknowledge_ai_analyst_incident_event_command)

    # GIVEN an integration is configured and fetch incidents
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/ack_response.json')
    requests_mock.post('https://mock.darktrace.com/aianalyst/acknowledge',
                       json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
    }
    integration_response = acknowledge_ai_analyst_incident_event_command(client, args)
    expected_response = util_load_json('test_data/formatted_ack.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'


def test_unacknowledge_ai_analyst_incident_event_command(requests_mock):
    """Tests acknowledge_ai_analyst_incident_event_command command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAIA import (Client,
                              unacknowledge_ai_analyst_incident_event_command)

    # GIVEN an integration is configured and fetch incidents
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/unack_response.json')
    requests_mock.post('https://mock.darktrace.com/aianalyst/unacknowledge',
                       json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
    }
    integration_response = unacknowledge_ai_analyst_incident_event_command(client, args)
    expected_response = util_load_json('test_data/formatted_unack.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'


def test_get_ai_analyst_incident_group_from_eventId(requests_mock):
    from DarktraceAIA import (
        Client, get__ai_analyst_incident_group_from_eventId_command)
    eventId = "bc64f242-ce29-4f35-bc94-230991116564"
    mock_api_response = util_load_json('test_data/group_response.json')
    requests_mock.get('https://mock.darktrace.com/aianalyst/groups?uuid=' + eventId,
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    args = {
        'eventId': eventId,
    }

    integration_response = get__ai_analyst_incident_group_from_eventId_command(client, args)
    expected_response = util_load_json('test_data/formatted_group_response.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AIAnalyst'
    assert integration_response.outputs_key_field == 'groupId'

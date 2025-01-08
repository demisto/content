import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents function
    """
    from Cognni import Client, fetch_incidents

    mock_response = util_load_json('test_data/fetch_incidents.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    first_fetch_time = 1600000000
    last_run = {}
    min_severity = 0
    next_run, incidents = fetch_incidents(client=client,
                                          events_limit=10,
                                          first_fetch_time=first_fetch_time,
                                          last_run=last_run,
                                          min_severity=min_severity)

    assert next_run['last_fetch'] > first_fetch_time
    assert len(incidents) == 8


def test_get_event_with_special_character(requests_mock):
    """Tests the get event command when event id contains special characters
    """
    from Cognni import Client, get_event_command

    mock_response = util_load_json('test_data/get_event_with_special_character.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    event_id = 'a!@#'
    args = {
        "event_id": event_id
    }
    response = get_event_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.raw_response is None


def test_get_event_with_whitespace(requests_mock):
    """Tests the get event command when event id contains whitespaces
    """
    from Cognni import Client, get_event_command

    mock_response = util_load_json('test_data/get_event_with_whitespace.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    event_id = 'Test with whitespaces'
    args = {
        "event_id": event_id
    }
    response = get_event_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.raw_response is None


def test_get_insight_with_whitespace(requests_mock):
    """Tests the get insight command when insight id contains whitespaces
    """
    from Cognni import Client, get_insight_command

    mock_response = util_load_json('test_data/get_insight_with_whitespace.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    insight_id = 'Test with whitespaces'
    args = {
        "insight_id": insight_id
    }
    response = get_insight_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.outputs_prefix == 'Cognni.insight'
    assert response.raw_response['id'] is None


def test_get_insight_with_special_characters(requests_mock):
    """Tests the get insight command with unexist insight id
      """
    from Cognni import Client, get_insight_command

    mock_response = util_load_json('test_data/get_insight_with_special_characters.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    insight_id = 'a!@#$%^&*()1'
    args = {
        "insight_id": insight_id
    }
    response = get_insight_command(client, args)

    assert response.raw_response['id'] is None


def test_get_event(requests_mock):
    """Tests the get event command
    """
    from Cognni import Client, get_event_command

    mock_response = util_load_json('test_data/get_event.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    event_id = 'df247df1-dd27-4bba-ac04-bc7d5dbf414c'
    args = {
        "event_id": event_id
    }
    response = get_event_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.outputs_prefix == 'Cognni.event'
    assert response.raw_response['id'] == event_id


def test_get_event_with_unknown_id(requests_mock):
    from Cognni import Client, get_event_command

    mock_response = util_load_json('test_data/get_event_with_unknown_id.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    event_id = 'df247df1-dd27-4bba-ac04-bc7d5dbf414d'
    args = {
        "event_id": event_id
    }
    response = get_event_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.raw_response is None


def test_get_insight(requests_mock):
    """Tests the get insight command
    """
    from Cognni import Client, get_insight_command

    mock_response = util_load_json('test_data/get_insight.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    insight_id = '740b5296-6d62-41e5-b0d7-1a7d5081f9cb'
    args = {
        "insight_id": insight_id
    }
    response = get_insight_command(client, args)

    # assert response.outputs[0] == mock_response
    assert response.outputs_prefix == 'Cognni.insight'
    assert response.raw_response['id'] == insight_id


def test_get_insight_with_unknown_id(requests_mock):
    from Cognni import Client, get_insight_command

    mock_response = util_load_json('test_data/get_insight_with_unknown_id.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    insight_id = '1234'
    args = {
        "insight_id": insight_id
    }
    response = get_insight_command(client, args)

    assert response.raw_response['id'] is None


def test_fetch_insights(requests_mock):
    """Tests the fetch-insights command
    """
    from Cognni import Client, fetch_insights_command

    mock_response = util_load_json('test_data/fetch_insights.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    args = {
        "min_severity": 0
    }
    response = fetch_insights_command(client, args)

    assert response.outputs_prefix == 'Cognni.insights'
    assert len(response.raw_response) == 1


def test_fetch_insight_with_small_severity(requests_mock):
    from Cognni import Client, fetch_insights_command

    mock_response = util_load_json('test_data/fetch_insights_with_small_severity.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    min_severity = -1
    args = {
        "min_severity": min_severity
    }
    response = fetch_insights_command(client, args)

    assert response.outputs_prefix == 'Cognni.insights'
    if len(response.raw_response) > 0:
        for answer in response.raw_response:
            assert answer['severity'] >= min_severity


def test_fetch_insight_with_large_severity(requests_mock):
    from Cognni import Client, fetch_insights_command

    mock_response = util_load_json('test_data/fetch_insights_with_large_severity.json')
    requests_mock.post('https://localhost/intelligence/data/graphql',
                       json=mock_response)

    client = Client(
        base_url='https://localhost',
        verify=False,
        headers={
            'Authorization': 'Bearer some_api_key'
        }
    )

    min_severity = 10
    args = {
        "min_severity": min_severity
    }
    response = fetch_insights_command(client, args)

    assert response.outputs_prefix == 'Cognni.insights'
    assert len(response.raw_response) == 0


def test_convert_file_event_to_incident():
    from Cognni import convert_file_event_to_incident

    mock_file_event = util_load_json('test_data/file_event.json')

    result = convert_file_event_to_incident(mock_file_event)

    assert result['name'] == "event-file-name-1"
    assert result['details'] == "This is a description"
    assert result['severity'] == 3


def test_flatten_event_file_items():
    from Cognni import flatten_event_file_items

    mock_event_with_file_items = util_load_json('test_data/event_with_file_items.json')

    result = flatten_event_file_items(mock_event_with_file_items)

    assert len(result) == 1

    item = result[0]
    assert item['eventId'] == "event-id-1"
    assert item['fileId'] == "file-id-1"
    assert item['severity'] == 3
    assert item["sourceApplication"] == "source-app"
    assert item['eventType'] == "Type1"


def test_flatten_event_file_items_with_0_items():
    from Cognni import flatten_event_file_items

    mock_event_with_0_file_items = util_load_json('test_data/event_with_0_file_items.json')

    result = flatten_event_file_items(mock_event_with_0_file_items)

    assert len(result) == 0

import TeamViewerEventCollector
from freezegun import freeze_time


def test_constructor():
    from TeamViewerEventCollector import Client
    base_url = "https://example.com"
    verify = False
    proxy = "http://proxy.example.com"
    headers = {"Authorization": "Bearer token"}
    client = Client(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
    assert client._base_url == base_url
    assert client._verify == verify
    assert client._headers == headers


# Tests that the http_request method handles an invalid request
# (invalid parameters and body) and returns an error response from the api.
def test_invalid_request(mocker):
    from TeamViewerEventCollector import Client
    # Mocking the http_request method to return an error response
    mocker.patch.object(Client, 'http_request', return_value={'error': 'Invalid request'})
    # Creating a client instance and calling the http_request method with invalid parameters and body
    client = Client(base_url='https://example.com', verify=False, proxy=False, headers=None)
    response = client.http_request(params='invalid', body='invalid')
    # Asserting that the response contains the expected error message
    assert response == {'error': 'Invalid request'}


# Tests that the function successfully retrieves the requested number of events.
def test_search_events_retrieves_requested_number_of_events(mocker):
    # Arrange
    client = TeamViewerEventCollector.Client(base_url="https://example.com", verify=False, proxy=False, headers={})
    limit = 5
    expected_results = [{"event_id": i} for i in range(1, limit + 1)]
    response = {"AuditEvents": expected_results}
    mocker.patch.object(client, 'http_request', return_value=response)

    # Act
    results = TeamViewerEventCollector.search_events(client=client, limit=limit)

    # Assert
    assert len(results[0]) == limit
    assert results[0] == expected_results


# Tests that the function retrieves all available events when
# the limit is set to a number higher than the number of available events.
def test_search_events_retrieves_all_available_events_when_limit_is_higher_than_number_of_available_events(mocker):
    # Arrange
    client = TeamViewerEventCollector.Client(base_url="https://example.com", verify=False, proxy=False, headers={})
    limit = 10
    expected_results = [{"event_id": i} for i in range(1, 6)]
    response = {"AuditEvents": expected_results, "ContinuationToken": "abc123"}
    mocker.patch.object(client, 'http_request', side_effect=[response, {"AuditEvents": [{"event_id": 6}]}, {}])

    # Act
    results = TeamViewerEventCollector.search_events(client=client, limit=limit)

    # Assert
    assert len(results[0]) == 6
    assert results[0] == expected_results + [{"event_id": 6}]


# Tests that the function retrieves no events when the limit is set to 0.
def test_search_events_retrieves_no_events_when_limit_is_zero(mocker):
    # Arrange
    client = TeamViewerEventCollector.Client(base_url="https://example.com", verify=False, proxy=False, headers={})
    limit = 0
    mocker.patch.object(client, 'http_request', return_value={"AuditEvents": [{"event_id": 1}]})

    # Act
    results = TeamViewerEventCollector.search_events(client=client, limit=limit)

    # Assert
    assert len(results[0]) == 0


# Tests that the function retrieves no events when the time parameters
# in the body are set to a time range with no events.
def test_search_events_retrieves_no_events_when_time_parameters_have_no_events(mocker):
    """
    Given:
    - A client object
    - A limit parameter
    - A body parameter with time parameters set to a time range with no events

    When:
    - Calling the search_events function

    Then:
    - Ensure that the function retrieves no events
    """
    mock_http_request = mocker.patch.object(TeamViewerEventCollector.Client, 'http_request',
                                            return_value={'AuditEvents': [], 'ContinuationToken': None})
    client = TeamViewerEventCollector.Client(base_url='https://test.com', verify=False, proxy=False, headers={})
    results = TeamViewerEventCollector.search_events(client=client, limit=10,
                                                     body={'StartTimeUtc': '2022-01-01T00:00:00Z',
                                                           'EndTimeUtc': '2022-01-02T00:00:00Z'})
    assert len(results[0]) == 0
    mock_http_request.assert_called_once()


# response or a response with missing fields.
def test_search_events_handles_empty_response_and_missing_fields(mocker):
    """
    Given:
    - A client object
    - A limit parameter
    - An API response with missing fields or an empty response

    When:
    - Calling the search_events function

    Then:
    - Ensure that the function handles the case and returns an empty list
    """
    mock_http_request = mocker.patch.object(TeamViewerEventCollector.Client, 'http_request', return_value={})
    client = TeamViewerEventCollector.Client(base_url='https://test.com', verify=False, proxy=False, headers={})
    results = TeamViewerEventCollector.search_events(client=client, limit=10)
    assert len(results[0]) == 0
    mock_http_request.assert_called_once()


@freeze_time("2023-04-16T10:46:49Z")
def test_fetch_events_command(mocker):
    """
    Given:
    - A client object
    - A maximum number of events to fetch
    - A last run dictionary with no last fetch time
    - A first fetch time

    When:
    - Calling the fetch_events_command function

    Then:
    - Ensure the function returns the correct next run dictionary and events list
    """
    from TeamViewerEventCollector import Client, fetch_events_command, DATE_FORMAT
    from datetime import datetime
    client = Client(base_url='https://test.com', verify=False, proxy=False, headers={})
    max_fetch = 50
    last_run = {'last_fetch': None}
    first_fetch_time = datetime(2022, 1, 1, 0, 0, 0)
    expected_body = {
        "StartDate": first_fetch_time.strftime(DATE_FORMAT),
        "EndDate": datetime.utcnow().strftime(DATE_FORMAT)
    }
    expected_next_run = {'last_fetch': '2023-04-16T10:46:49Z'}
    expected_events = [{'id': 1, 'Timestamp': '2023-01-01T01:00:00Z'}, {'id': 2, 'Timestamp': "2023-04-16T10:46:49Z"}]

    mocker.patch('datetime.datetime.utcnow', return_value=datetime(2023, 4, 16, 10, 46, 49))
    http_request_mock = mocker.patch.object(TeamViewerEventCollector.Client, 'http_request',
                                            return_value={'AuditEvents': expected_events})
    next_run, events = fetch_events_command(client, max_fetch, last_run, first_fetch_time)

    assert next_run == expected_next_run
    assert events == expected_events
    http_request_mock.assert_called_once_with(params={}, body=expected_body)


def test_add_time_key():
    from TeamViewerEventCollector import add_time_key_to_events
    events = [{"Timestamp": "2022-01-01T00:00:00Z", "data": "example data"}]
    result = add_time_key_to_events(events)
    assert result == [{"Timestamp": "2022-01-01T00:00:00Z", "_time": "2022-01-01T00:00:00Z", "data": "example data"}]


def test_main_function(mocker):
    """
    Given:
    - Valid parameters for the main function.

    When:
    - Calling the main function.

    Then:
    - Ensure the function executes successfully with valid parameters.
    """
    from TeamViewerEventCollector import main, Client
    import demistomock as demisto

    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://test.com',
        'credentials': {'Script Token': 'test_token'},
        'insecure': False,
        'proxy': False,
        'first_fetch': '3 days',
        'max_fetch': '300'
    })
    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'command', return_value='fetch-events')
    mocker.patch.object(demisto, 'getLastRun', return_value={'last_fetch': '2023-04-16T10:46:49Z'})
    mocker.patch.object(demisto, 'setLastRun')
    demisto_debug_mocker = mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    demisto_results_mocker = mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={})
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(TeamViewerEventCollector, 'send_events_to_xsiam')
    mocker.patch.object(Client, 'http_request')
    # mocker.patch.object(Client, '__init__', return_value=None)
    demisto_results_mocker = mocker.patch.object(TeamViewerEventCollector, 'fetch_events_command',
                                                 return_value=({'last_fetch': '2023-04-16T10:46:49Z'},
                                                               [{'id': 1, 'Timestamp': '2023-01-01T01:00:00Z'},
                                                                {'id': 2, 'Timestamp': "2023-04-16T10:46:49Z"}]))
    main()
    demisto_debug_mocker.assert_called_once_with('Command being called is fetch-events')
    demisto_results_mocker.assert_called_once()

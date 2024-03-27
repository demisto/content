import pytest
from GenetecSecurityCenterEventCollector import Client, main
from unittest import mock
import demistomock as demisto

INCIDENT_NO_ONE = {
    'Id': 1,
    'Guid': 1,
    'ModificationTimeStamp': '2024-02-21T23:21:33.96Z',
    'Value': "<AuditData><EId>1</EId></AuditData>"
}
INCIDENT_NO_TWO = {
    'Id': 2,
    'Guid': 2,
    'ModificationTimeStamp': '2024-02-22T23:21:33.96Z',
    'Value': "<AuditData><EId>2</EId></AuditData>"
}
INCIDENT_NO_THREE = {
    'Id': 3,
    'Guid': 3,
    'ModificationTimeStamp': '2024-02-23T23:21:33.96Z',
    'Value': "<AuditData><EId>3</EId></AuditData>"
}
INCIDENT_NO_FOUR = {
    'Id': 4,
    'Guid': 4,
    'ModificationTimeStamp': '2024-02-24T23:21:33.96Z',
    'Value': "<AuditData><EId>4</EId></AuditData>"
}


def mock_http_response(
    content=None,
):
    mock_resp = mock.Mock()
    mock_resp.content = content
    return mock_resp


def get_client() -> Client:
    return Client("www.test.com", "username", "password", False, False, "2", "app_id")


def test_test_module_success(mocker):
    """
    Validate that in case of a successful response from the BaseClient's _http_request
    The Client's http_request will return the response and test-module will return 'ok'.
    """
    from GenetecSecurityCenterEventCollector import test_module
    client = get_client()
    mock_response = mock_http_response(content="""{"Rsp": {"Status": "OK", "Result": "Result"}}""")
    mocker.patch.object(client, "_http_request", return_value=mock_response)
    assert test_module(client=client) == "ok"


def test_test_module_failure(mocker):
    """
    Validate that in case of an unsuccessful response from the BaseClient's _http_request.
    The Client's http_request will raise an error with the result section as the message and test-module will fail as well..
    """
    from GenetecSecurityCenterEventCollector import test_module
    client = get_client()
    mock_response = mock_http_response(content="""{"Rsp": {"Status": "Fail", "Result": "Failed the http request."}}""")
    mocker.patch.object(client, "_http_request", return_value=mock_response)
    try:
        test_module(client=client)
    except Exception as err:
        assert "Failed the http request." in str(err)


@pytest.mark.parametrize('first_iteration_response, second_iteration_response, expected_events_len_first_call,'
                         'expected_events_len_second_call, expected_last_run_first_iteration, expected_last_run_second_iteration,'
                         'expected_events_first_call, expected_events_second_call',
                         [
                             ([INCIDENT_NO_ONE, INCIDENT_NO_TWO.copy(), INCIDENT_NO_THREE, INCIDENT_NO_FOUR],
                              [INCIDENT_NO_TWO, INCIDENT_NO_THREE, INCIDENT_NO_FOUR], 2, 1,
                              {'audit_cache': [1, 2], 'start_time': '2024-02-22T23:21:33'},
                              {'audit_cache': [3], 'start_time': '2024-02-23T23:21:33'},
                              [
                                  {
                                      'Id': 1,
                                      'Guid': 1,
                                      'ModificationTimeStamp': '2024-02-21T23:21:33.96Z',
                                      '_time': '2024-02-21T23:21:33.96Z',
                                      'Value': {'AuditData': {'EId': '1'}}
                                  },
                                  {
                                      'Id': 2,
                                      'Guid': 2,
                                      'ModificationTimeStamp': '2024-02-22T23:21:33.96Z',
                                      '_time': '2024-02-22T23:21:33.96Z',
                                      'Value': {'AuditData': {'EId': '2'}}
                                  }
                             ],
                                 [
                                  {
                                      'Id': 3,
                                      'Guid': 3,
                                      'ModificationTimeStamp': '2024-02-23T23:21:33.96Z',
                                      '_time': '2024-02-23T23:21:33.96Z',
                                      'Value': {'AuditData': {'EId': '3'}}
                                  }
                             ])
                         ])
def test_fetch_events_command(
        mocker, first_iteration_response,
        second_iteration_response,
        expected_events_len_first_call,
        expected_events_len_second_call,
        expected_last_run_first_iteration,
        expected_last_run_second_iteration,
        expected_events_first_call,
        expected_events_second_call):
    """Testing two consecutive calls to the fetch events command.
        The flow:
        - General mocks & preparations.
        - First call.
        - Asserting first call results: The last_run object, the number of retrieved events, and the events content.
        - Second call.
        - Asserting second call results: The last_run object, the number of retrieved events, and the events content.
    """
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, "params", return_value={
        "url": "http://test.com",
        "credentials": {"identifier": "username", "password": "password"},
        "app_id": "app_id",
        "max_fetch": "2"
    })
    send_events_mock = mocker.patch('GenetecSecurityCenterEventCollector.send_events_to_xsiam')
    mocker.patch("GenetecSecurityCenterEventCollector.Client.http_request", return_value=first_iteration_response)
    main()
    assert demisto.setLastRun.call_args[0][0] == expected_last_run_first_iteration
    first_call_events = send_events_mock.call_args.kwargs["events"]
    assert len(first_call_events) == expected_events_len_first_call
    assert first_call_events == expected_events_first_call
    mocker.patch("GenetecSecurityCenterEventCollector.Client.http_request", return_value=second_iteration_response)
    main()
    assert demisto.setLastRun.call_args[0][0] == expected_last_run_second_iteration
    second_call_events = send_events_mock.call_args.kwargs["events"]
    assert len(second_call_events) == expected_events_len_second_call
    assert second_call_events == expected_events_second_call

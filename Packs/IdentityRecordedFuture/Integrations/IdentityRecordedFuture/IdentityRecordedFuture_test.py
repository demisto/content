from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import vcr as vcrpy
from IdentityRecordedFuture import Client

CASSETTES = Path(__file__).parent / "test_data"
DATETIME_STR_VALUE = "2021-12-08T12:10:21.837Z"


def filter_out_whoami(response):
    import json

    body = response["body"]["string"]
    try:
        body.decode("utf-8")
        json_blob = json.loads(body)
        json_blob.pop("api_key", None)
        response["body"]["string"] = json.dumps(json_blob).encode("utf-8")
    except UnicodeDecodeError:
        pass  # It's not a json string
    return response


vcr = vcrpy.VCR(
    serializer="yaml",
    cassette_library_dir=str(CASSETTES),
    record_mode="once",
    filter_headers=[("X-RFToken", "XXXXXX")],
    before_record_response=filter_out_whoami,
)


def util_load_json(path):
    import json

    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def create_client() -> Client:
    import os

    base_url = "https://api.recordedfuture.com/gw/xsoar-identity/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": "Cortex_XSOAR/2.0 Cortex_XSOAR_unittest_0.1",
    }

    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=None)


@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_client_whoami(mock_http_request: Mock) -> None:
    """Test whoami()."""
    client = create_client()
    response = {1: 1}
    mock_http_request.return_value = response
    result = client.whoami()
    assert response == result
    mock_http_request.assert_called_once_with(
        method="get",
        url_suffix="info/whoami",
        timeout=60,
    )


@patch("IdentityRecordedFuture.Client._call")
def test_credentials_search(mock_call: Mock) -> None:
    """Test credentials_search()."""
    client = create_client()
    client.credentials_search()
    mock_call.assert_called_once_with(url_suffix="/v2/identity/credentials/search")


@patch("IdentityRecordedFuture.Actions._process_result_actions")
def test_credentials_search_process_result(process_result_mock: Mock) -> None:
    """Test search identities code."""
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    some_random_data = "data"
    client.credentials_search.return_value = some_random_data
    process_result_mock.return_value = some_random_data
    action_result = actions.identity_search_command()
    assert some_random_data == action_result
    client.credentials_search.assert_called_once()
    process_result_mock.assert_called_once_with(response=some_random_data)


@patch("IdentityRecordedFuture.Client._call")
def test_credentials_lookup(mock_call: Mock) -> None:
    """Test credentials_lookup()."""
    client = create_client()
    client.credentials_lookup()
    mock_call.assert_called_once_with(url_suffix="/v2/identity/credentials/lookup")


@patch("IdentityRecordedFuture.Actions._process_result_actions")
def test_credentials_lookup_process_result(process_result_mock: Mock) -> None:
    """Test lookup identities code."""
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    some_random_data = "data"
    client.credentials_lookup.return_value = some_random_data
    process_result_mock.return_value = some_random_data
    action_result = actions.identity_lookup_command()
    assert some_random_data == action_result
    client.credentials_lookup.assert_called_once()
    process_result_mock.assert_called_once_with(response=some_random_data)


@patch("IdentityRecordedFuture.Client._call")
def test_password_lookup(mock_call: Mock) -> None:
    """Test password_lookup()."""
    client = create_client()
    client.password_lookup()
    mock_call.assert_called_once_with(url_suffix="/v2/identity/password/lookup")


@patch("IdentityRecordedFuture.Actions._process_result_actions")
def test_password_lookup_process_result(process_result_mock: Mock) -> None:
    """Test password lookup code."""

    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    some_random_data = "data"
    client.password_lookup.return_value = some_random_data
    process_result_mock.return_value = some_random_data
    action_result = actions.password_lookup_command()
    assert some_random_data == action_result
    client.password_lookup.assert_called_once()
    process_result_mock.assert_called_once_with(response=some_random_data)


@patch("IdentityRecordedFuture.demisto")
@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_call(mock_http_request: Mock, mocked_demisto: Mock):
    """Test _call()."""

    client = create_client()
    STATUS_TO_RETRY = [500, 501, 502, 503, 504]

    mock_demisto_last_run = {"last_run": "mock"}
    mock_demisto_command = "command"
    mock_demisto_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}
    mock_demisto_params = {"someparam": "some param value"}

    mocked_demisto.command.return_value = mock_demisto_command
    mocked_demisto.getLastRun.return_value = mock_demisto_last_run
    mocked_demisto.args.return_value = mock_demisto_command_args
    mocked_demisto.params.return_value = mock_demisto_params
    http_response = {"some": "http response"}
    mock_http_request.return_value = http_response

    mock_url_suffix = "mock_url_suffix"

    result = client._call(url_suffix=mock_url_suffix)

    json_data = {
        "demisto_args": mock_demisto_command_args,
        "demisto_params": mock_demisto_params,
        "demisto_command": mock_demisto_command,
        "demisto_last_run": mock_demisto_last_run,
    }

    mock_http_request.assert_called_once_with(
        method="post",
        url_suffix=mock_url_suffix,
        json_data=json_data,
        timeout=90,
        retries=3,
        status_list_to_retry=STATUS_TO_RETRY,
    )

    assert result == http_response


@patch("IdentityRecordedFuture.return_error")
@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_call_return_error(mock_http_request: Mock, return_error_mock: Mock):
    """Test _call() when error message was returned."""
    from CommonServerPython import DemistoException

    client = create_client()
    mock_url_suffix = "mock_url_suffix"
    error_message_res = {"message": "error"}
    mock_error_response = Mock()
    mock_error_response.json.return_value = error_message_res
    mock_http_request.side_effect = DemistoException(
        message="", res=mock_error_response
    )
    client._call(url_suffix=mock_url_suffix)
    return_error_mock.assert_called_once_with(**error_message_res)


@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_call_return_error_not_json(mock_http_request: Mock):
    """Test _call() when error message was returned and it is not json serializable."""
    import json

    from CommonServerPython import DemistoException

    client = create_client()
    mock_url_suffix = "mock_url_suffix"
    mock_error_response = Mock()
    mock_error_response.json.side_effect = json.JSONDecodeError(
        "some not json error", "some", 3
    )
    mock_http_request.side_effect = DemistoException(
        message="", res=mock_error_response
    )
    with pytest.raises(DemistoException):
        client._call(url_suffix=mock_url_suffix)


@patch("IdentityRecordedFuture.CommandResults")
@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_call_return_http_404_error(
    mock_http_request: Mock, command_results_mock: Mock
):
    """Test _call() when error message was returned."""
    from CommonServerPython import DemistoException

    client = create_client()
    mock_url_suffix = "mock_url_suffix"
    mock_http_request.side_effect = DemistoException("There is HTTP 404 error")
    client._call(url_suffix=mock_url_suffix)
    command_results_mock.assert_called_once_with(
        outputs_prefix="",
        outputs={},
        raw_response={},
        readable_output="No results found.",
        outputs_key_field="",
    )


@patch("IdentityRecordedFuture.BaseClient._http_request")
def test_call_return_http_error(mock_http_request: Mock):
    """Test _call() when error message was returned."""
    from CommonServerPython import DemistoException

    client = create_client()
    mock_url_suffix = "mock_url_suffix"
    mock_http_request.side_effect = DemistoException("Some error from the Server")
    with pytest.raises(DemistoException):
        client._call(url_suffix=mock_url_suffix)


def test_call_with_kwargs(mocker):
    """
    Test the `_call` method to ensure it correctly processes
    additional keyword arguments and sends a request with the expected parameters.
    """

    import os

    import demistomock as demisto

    client = create_client()
    STATUS_TO_RETRY = [500, 501, 502, 503, 504]

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_http_request = mocker.patch.object(client, "_http_request")

    mock_url_suffix = "mock_url_suffix"

    client._call(url_suffix=mock_url_suffix, timeout=120, any_other_kwarg=True)

    json_data = {
        "demisto_command": mock_command_name,
        "demisto_args": mock_command_args,
        "demisto_params": {},
        "demisto_last_run": {"lastRun": "2018-10-24T14:13:20+00:00"},
    }

    mock_http_request.assert_called_once_with(
        method="post",
        url_suffix=mock_url_suffix,
        json_data=json_data,
        timeout=120,
        retries=3,
        status_list_to_retry=STATUS_TO_RETRY,
        any_other_kwarg=True,
    )


def test_call_returns_response(mocker):
    """
    Test that the `_call` method correctly returns the response from the HTTP request.
    """

    import os

    import demistomock as demisto

    client = create_client()

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_response = {"response": {"data": "mock data"}}

    mocker.patch.object(client, "_http_request", return_value=mock_response)

    mock_url_suffix = "mock_url_suffix"

    response = client._call(url_suffix=mock_url_suffix)
    assert response == mock_response


def test_call_response_processing_return_error(mocker):
    """
    Test that the `_call` method correctly processes a return_error response.
    """

    import os

    import demistomock as demisto

    client = create_client()

    STATUS_TO_RETRY = [500, 501, 502, 503, 504]

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_return_error = mocker.patch("IdentityRecordedFuture.return_error")

    mock_http_request = mocker.patch.object(
        client,
        "_http_request",
        return_value={"return_error": {"message": "mock error"}},
    )

    mock_url_suffix = "mock_url_suffix"

    client._call(url_suffix=mock_url_suffix)

    json_data = {
        "demisto_command": mock_command_name,
        "demisto_args": mock_command_args,
        "demisto_params": {},
        "demisto_last_run": {"lastRun": "2018-10-24T14:13:20+00:00"},
    }

    mock_http_request.assert_called_once_with(
        method="post",
        url_suffix=mock_url_suffix,
        json_data=json_data,
        timeout=90,
        retries=3,
        status_list_to_retry=STATUS_TO_RETRY,
    )

    mock_return_error.assert_called_once_with(message="mock error")


def test_call_response_processing_404(mocker):
    """
    Test that the `_call` method correctly handles a 404 error response and returns the appropriate CommandResults.
    """

    import os

    import demistomock as demisto
    from CommonServerPython import CommandResults, DemistoException

    client = create_client()

    STATUS_TO_RETRY = [500, 501, 502, 503, 504]

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mocker.patch("IdentityRecordedFuture.return_error")

    def mock_http_request_method(*args, **kwargs):
        # Imitate how CommonServerPython handles bad responses (when status code not in ok_codes,
        # or if ok_codes=None - it uses requests.Response.ok to check whether response is good).
        raise DemistoException("404")

    mocker.patch.object(client, "_http_request", mock_http_request_method)

    spy_http_request = mocker.spy(client, "_http_request")

    mock_url_suffix = "mock_url_suffix"

    result = client._call(url_suffix=mock_url_suffix)

    json_data = {
        "demisto_command": mock_command_name,
        "demisto_args": mock_command_args,
        "demisto_params": {},
        "demisto_last_run": {"lastRun": "2018-10-24T14:13:20+00:00"},
    }

    spy_http_request.assert_called_once_with(
        method="post",
        url_suffix=mock_url_suffix,
        json_data=json_data,
        timeout=90,
        retries=3,
        status_list_to_retry=STATUS_TO_RETRY,
    )

    assert isinstance(result, CommandResults)

    assert result.outputs_prefix == ""
    assert result.outputs_key_field == ""
    assert result.outputs == {}
    assert result.raw_response == {}
    assert result.readable_output == "No results found."


def test_call_DemistoException_res_json_error(mocker):
    """Test _call when err.res.json() raises an exception (e.g., JSONDecodeError)."""
    import json

    import demistomock as demisto
    from CommonServerPython import DemistoException

    client = create_client()

    mocker.patch.object(demisto, "command", return_value="command_name")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})

    class MockResponse:
        def json(self):
            raise json.JSONDecodeError("Expecting value", "doc", 0)

    def mock_http_request(*args, **kwargs):
        err = DemistoException("Error with response")
        err.res = MockResponse()
        raise err

    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)

    with pytest.raises(DemistoException):
        client._call(url_suffix="mock_url_suffix")


def test_call_DemistoException_res_None(mocker):
    """Test _call when DemistoException has no response (err.res is None)."""

    import demistomock as demisto
    from CommonServerPython import DemistoException

    client = create_client()

    mocker.patch.object(demisto, "command", return_value="command_name")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})

    def mock_http_request(*args, **kwargs):
        err = DemistoException("Some error without response")
        err.res = None
        raise err

    mocker.patch.object(client, "_http_request", side_effect=mock_http_request)

    with pytest.raises(DemistoException) as excinfo:
        client._call(url_suffix="mock_url_suffix")

    assert str(excinfo.value) == "Some error without response"


def test_fetch_incidents(mocker):
    """
    Test the `fetch_incidents` method to ensure it sends the correct request and processes the response as expected.
    """
    import os

    import demistomock as demisto

    client = create_client()

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}
    mock_params = {"param1": "param1 value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)
    mocker.patch.object(demisto, "params", return_value=mock_params)

    mock_last_run_dict = {"lastRun": "2022-08-31T12:12:20+00:00"}
    mocker.patch.object(demisto, "getLastRun", return_value=mock_last_run_dict)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.fetch_incidents()

    mock_call.assert_called_once_with(
        timeout=120,
        url_suffix="/playbook_alert/fetch",
    )

    assert response == mock_call_response


def test_playbook_alert_search(mocker):
    """
    Test the `search_playbook_alerts` method to ensure it sends the correct request and processes the response as expected.
    """
    import os

    import demistomock as demisto

    client = create_client()

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.search_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/search")

    assert response == mock_call_response


def test_playbook_alert_details_multi_input(mocker):
    """
    Test the `details_playbook_alerts` method to ensure it correctly processes multiple input arguments.
    """
    import os

    import demistomock as demisto

    client = create_client()

    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    mock_command_name = "command_name"
    mock_alert_ids = "input1,mock_value"
    mock_detail_sections = "input1,mock_value"
    mock_command_args = {
        "alert_ids": mock_alert_ids,
        "detail_sections": mock_detail_sections,
    }

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.details_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/lookup")

    assert response == mock_call_response


def test_playbook_alert_update_multi_input(mocker):
    """
    Test the `update_playbook_alerts` method to ensure it correctly processes multiple input arguments.
    """
    import os

    import demistomock as demisto

    client = create_client()

    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    mock_command_name = "command_name"
    mock_alert_ids = "input1,input2"

    mock_command_args = {"alert_ids": mock_alert_ids}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.update_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/update")

    assert response == mock_call_response


def test_playbook_alert_search_multi_input(mocker):
    """
    Test the `search_playbook_alerts` method to ensure it correctly processes multiple input arguments.
    """
    import os

    import demistomock as demisto

    client = create_client()

    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    mock_command_name = "command_name"
    mock_priority = "high"
    mock_detail_sections = "sdadwa,adinhw0ijd"
    mock_command_args = {
        "priority": mock_priority,
        "playbook_alert_status": mock_detail_sections,
    }

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.search_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/search")

    assert response == mock_call_response


def test_playbook_alert_details(mocker):
    """
    Test the `details_playbook_alerts` method to ensure it sends the correct request and processes the response as expected.
    """
    import os

    import demistomock as demisto

    client = create_client()

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.details_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/lookup")

    assert response == mock_call_response


def test_playbook_alert_update(mocker):
    """
    Test the `update_playbook_alerts` method to ensure it sends the correct request and processes the response as expected.
    """
    import os

    import demistomock as demisto

    client = create_client()

    # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
    os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

    # Mock demisto command and args.
    mock_command_name = "command_name"
    mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

    mocker.patch.object(demisto, "command", return_value=mock_command_name)
    mocker.patch.object(demisto, "args", return_value=mock_command_args)

    mock_call_response = {"response": {"data": "mock response"}}
    mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

    response = client.update_playbook_alerts()

    mock_call.assert_called_once_with(url_suffix="/playbook_alert/update")

    assert response == mock_call_response


def test_actions_init(mocker):
    """
    Test the initialization of the `Actions` class to ensure the client is correctly assigned.
    """
    from IdentityRecordedFuture import Actions

    mock_client = mocker.Mock()
    actions = Actions(mock_client)
    assert actions.client == mock_client


def test_process_result_actions_returns_list() -> None:
    """Test result processing function with the case when we received 404 error."""

    from CommonServerPython import CommandResults
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    response = CommandResults()
    result = actions._process_result_actions(response)
    assert isinstance(result, list)


def test_process_result_actions_returns_none() -> None:
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    response = {}
    result = actions._process_result_actions(response)
    assert result is None


def test_process_result_actions_404_error() -> None:
    """Test result processing function with the case when we received 404 error."""

    from CommonServerPython import CommandResults
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    response = CommandResults()
    result = actions._process_result_actions(response)
    assert [response] == result


def test_process_result_actions_wrong_type() -> None:
    """Test result processing function with the case when we received string data."""
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)
    response = "Some bad response from API"
    result = actions._process_result_actions(response)
    assert result is None


def test_process_result_actions_no_key_value() -> None:
    """Test result processing function with the case when we received date without action_result key."""
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)
    response = {}
    result = actions._process_result_actions(response)
    assert result is None


def test_process_result_actions() -> None:
    """Test result processing function with the case when we received good data."""
    from CommonServerPython import CommandResults
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)
    response = {"action_result": {"readable_output": "data"}}
    results = actions._process_result_actions(response)
    for x in results:
        assert isinstance(x, CommandResults)


def test_process_result_actions_404(mocker):
    """
    Test the `_process_result_actions` method to ensure it handles a CommandResults response correctly.
    """
    from CommonServerPython import CommandResults
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    # Test if response is CommandResults
    # (case when we got 404 on response, and it was processed in client._call() method).
    response = CommandResults(readable_output="Mock")
    result_actions = actions._process_result_actions(response=response)
    assert result_actions == [response]


def test_process_result_actions_response_is_not_dict(mocker):
    """
    Test the `_process_result_actions` method to ensure it returns None when the response is not a dictionary.
    """
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    # Test if response is not CommandResults and not Dict.
    response = "Mock string - not CommandResults and not dict"
    result_actions = actions._process_result_actions(response=response)  # type: ignore
    assert result_actions is None


def test_process_result_actions_no_or_empty_result_actions_in_response(mocker):
    """
    Test the `_process_result_actions` method to ensure it returns None when there are no result actions in the response.
    """
    from IdentityRecordedFuture import Actions

    client = Mock()
    actions = Actions(client)

    # Test no results_actions in response.
    response = {"data": "mock"}
    result_actions = actions._process_result_actions(response=response)
    assert result_actions is None

    # Test case when bool(results_actions) in response is False.
    response = {"data": "mock", "result_actions": None}
    result_actions = actions._process_result_actions(response=response)
    assert result_actions is None

    response = {"data": "mock", "result_actions": []}
    result_actions = actions._process_result_actions(response=response)
    assert result_actions is None

    response = {"data": "mock", "result_actions": {}}
    result_actions = actions._process_result_actions(response=response)
    assert result_actions is None


def test_process_result_actions_command_results_only(mocker):
    """
    Test the `_process_result_actions` method to ensure it processes a response containing CommandResults correctly.
    """
    from IdentityRecordedFuture import Actions, CommandResults

    client = Mock()
    actions = Actions(client)

    response = {
        "data": "mock",
        "result_actions": [
            {
                "CommandResults": {
                    "outputs_prefix": "mock_outputs_prefix",
                    "outputs": "mock_outputs",
                    "raw_response": "mock_raw_response",
                    "readable_output": "mock_readable_output",
                    "outputs_key_field": "mock_outputs_key_field",
                },
            }
        ],
    }
    result_actions = actions._process_result_actions(response=response)

    assert len(result_actions) == 1

    r_a = result_actions[0]

    assert isinstance(r_a, CommandResults)

    assert r_a.outputs_prefix == "mock_outputs_prefix"
    assert r_a.outputs == "mock_outputs"
    assert r_a.raw_response == "mock_raw_response"
    assert r_a.readable_output == "mock_readable_output"
    assert r_a.outputs_key_field == "mock_outputs_key_field"


def test_process_result_actions_with_invalid_actions(mocker):
    """Test processing result actions with invalid keys."""
    from CommonServerPython import CommandResults
    from IdentityRecordedFuture import Actions

    actions = Actions(rf_client=None)

    response = {
        "result_actions": [
            {"InvalidKey": {}},
            {
                "CommandResults": {
                    "outputs_prefix": "mock_prefix",
                    "outputs": "mock_outputs",
                }
            },
            {
                "CommandResults": {
                    "outputs_prefix": "another_prefix",
                    "outputs": "another_outputs",
                }
            },
        ]
    }

    result = actions._process_result_actions(response)

    assert len(result) == 2
    assert isinstance(result[0], CommandResults)
    assert result[0].outputs_prefix == "mock_prefix"
    assert result[0].outputs == "mock_outputs"
    assert isinstance(result[1], CommandResults)
    assert result[1].outputs_prefix == "another_prefix"
    assert result[1].outputs == "another_outputs"


def test_fetch_incidents_with_attachment(mocker):
    """
    Test the `fetch_incidents` method to ensure it correctly processes incidents with attachments.
    """
    import json

    import CommonServerPython as csp
    import demistomock as demisto
    from IdentityRecordedFuture import Actions

    client = create_client()
    screenshot_dict = {
        "panel_evidence_summary": {
            "screenshots": [
                {
                    "image_id": "an_id",
                    "base64": "YWJhc2U2NHN0cmluZw==",
                    "description": "vivid description of image",
                }
            ]
        }
    }
    mock_incidents_value = {
        "name": "incident_name",
        "rawJSON": json.dumps(screenshot_dict),
    }

    mock_demisto_last_run_value = "mock_demisto_last_run"

    mock_client_fetch_incidents_response = {
        "incidents": [mock_incidents_value],
        "demisto_last_run": mock_demisto_last_run_value,
    }

    mock_client_fetch_incidents = mocker.patch.object(
        client, "fetch_incidents", return_value=mock_client_fetch_incidents_response
    )

    mock_demisto_incidents = mocker.patch.object(demisto, "incidents")
    mock_demisto_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_file_result = mocker.patch.object(
        csp,
        "fileResult",
        return_value={"File": "mockfilepath", "FileID": "mock_file_id"},
    )

    mock_incidents_value.update(
        {
            "attachment": {
                "description": "vivid description of image",
                "showMediaFile": True,
            }.update(mock_file_result)
        }
    )
    actions = Actions(client)

    actions.fetch_incidents()

    mock_client_fetch_incidents.assert_called_once_with()

    mock_demisto_incidents.assert_called_once_with([mock_incidents_value])

    mock_demisto_set_last_run.assert_called_once_with(mock_demisto_last_run_value)


def test_transform_incidents_attachments_without_screenshots(mocker):
    """Test transforming incidents without screenshots."""
    import json

    from IdentityRecordedFuture import Actions

    incidents = [{"rawJSON": json.dumps({"panel_evidence_summary": {}})}]

    mock_fileResult = mocker.patch("IdentityRecordedFuture.fileResult")

    Actions._transform_incidents_attachments(incidents)

    assert "attachment" not in incidents[0]
    mock_fileResult.assert_not_called()


def test_fetch_incidents_with_incidents_present(mocker):
    """
    Test the `fetch_incidents` method to ensure it correctly processes incidents when incidents are present in the response.
    """
    import demistomock as demisto
    from IdentityRecordedFuture import Actions

    client = create_client()

    mock_incidents_value = [
        {"mock_incident_key1": "mock_incident_value1"},
        {"mock_incident_key2": "mock_incident_value2"},
    ]

    mock_demisto_last_run_value = "mock_demisto_last_run"

    mock_alerts_update_data_value = "mock_alerts_update_data_value"

    mock_client_fetch_incidents_response = {
        "incidents": mock_incidents_value,
        "demisto_last_run": mock_demisto_last_run_value,
        "data": "mock",
        "alerts_update_data": mock_alerts_update_data_value,
    }
    mock_client_fetch_incidents = mocker.patch.object(
        client, "fetch_incidents", return_value=mock_client_fetch_incidents_response
    )

    mock_demisto_incidents = mocker.patch.object(demisto, "incidents")
    mock_demisto_set_last_run = mocker.patch.object(demisto, "setLastRun")

    actions = Actions(client)

    actions.fetch_incidents()

    mock_client_fetch_incidents.assert_called_once_with()

    mock_demisto_incidents.assert_called_once_with(mock_incidents_value)
    mock_demisto_set_last_run.assert_called_once_with(mock_demisto_last_run_value)


def test_playbook_alert_details_command_with_result_actions(mocker):
    """
    Test the `playbook_alert_details_command` method to ensure it correctly processes result actions.
    """
    from IdentityRecordedFuture import Actions

    client = create_client()

    mock_response = "mock_response"

    mock_client_playbook_alert_details = mocker.patch.object(
        client, "details_playbook_alerts", return_value=mock_response
    )

    actions = Actions(client)

    mock_process_result_actions_return_value = (
        "mock_process_result_actions_return_value"
    )
    mock_process_result_actions = mocker.patch.object(
        actions,
        "_process_result_actions",
        return_value=mock_process_result_actions_return_value,
    )

    result = actions.playbook_alert_details_command()

    mock_client_playbook_alert_details.assert_called_once_with()

    mock_process_result_actions.assert_called_once_with(response=mock_response)

    # As there are some result actions - return those result actions.
    assert result == mock_process_result_actions_return_value


def test_playbook_alert_details_command_without_result_actions(mocker):
    """
    Test the `playbook_alert_details_command` method to ensure it handles the case when there are no result actions.
    """
    from IdentityRecordedFuture import Actions

    client = create_client()

    mock_response = "mock_response"

    mock_client_playbook_alert_details = mocker.patch.object(
        client, "details_playbook_alerts", return_value=mock_response
    )

    actions = Actions(client)

    mock_process_result_actions_return_value = None
    mock_process_result_actions = mocker.patch.object(
        actions,
        "_process_result_actions",
        return_value=mock_process_result_actions_return_value,
    )

    actions.playbook_alert_details_command()

    mock_client_playbook_alert_details.assert_called_once_with()

    mock_process_result_actions.assert_called_once_with(response=mock_response)


def test_playbook_alert_search_command_without_result_actions(mocker):
    """
    Test the `playbook_alert_search_command` method to ensure it handles the case when there are no result actions.
    """
    from IdentityRecordedFuture import Actions

    client = create_client()

    mock_response = "mock_response"

    mock_client_playbook_alert_search = mocker.patch.object(
        client, "search_playbook_alerts", return_value=mock_response
    )

    actions = Actions(client)

    mock_process_result_actions_return_value = None
    mock_process_result_actions = mocker.patch.object(
        actions,
        "_process_result_actions",
        return_value=mock_process_result_actions_return_value,
    )

    actions.playbook_alert_search_command()

    mock_client_playbook_alert_search.assert_called_once_with()

    mock_process_result_actions.assert_called_once_with(response=mock_response)


def test_playbook_alert_update_command(mocker):
    """
    Test the `playbook_alert_update_command` method to ensure it correctly processes result actions.
    """
    from IdentityRecordedFuture import Actions

    client = create_client()

    mock_response = "mock_response"

    mock_client_alert_set_status = mocker.patch.object(
        client, "update_playbook_alerts", return_value=mock_response
    )

    actions = Actions(client)

    mock_process_result_actions_return_value = (
        "mock_process_result_actions_return_value"
    )
    mock_process_result_actions = mocker.patch.object(
        actions,
        "_process_result_actions",
        return_value=mock_process_result_actions_return_value,
    )

    result = actions.playbook_alert_update_command()

    mock_client_alert_set_status.assert_called_once_with()

    mock_process_result_actions.assert_called_once_with(response=mock_response)

    assert result == mock_process_result_actions_return_value


def test_test_module(mocker):
    """
    Test the `test-module` command to ensure it verifies the integration setup correctly.
    """
    import platform

    import demistomock as demisto
    import IdentityRecordedFuture

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto, "demistoVersion", return_value={"version": "mock_version"}
    )
    mocker.patch.object(
        demisto, "params", return_value={"credential": {"password": "example"}}
    )
    mocker.patch.object(platform, "platform", return_value="mock_platform")
    mocker.patch.object(IdentityRecordedFuture.Client, "whoami")
    mocked_return_res = mocker.patch.object(IdentityRecordedFuture, "return_results")
    IdentityRecordedFuture.main()
    mocked_return_res.assert_called_with("ok")


def test_test_module_with_boom(mocker):
    """
    Test the `test-module` command to ensure it handles exceptions and returns the appropriate error message.
    """
    import platform

    import demistomock as demisto
    import IdentityRecordedFuture

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto, "demistoVersion", return_value={"version": "mock_version"}
    )
    mocker.patch.object(
        demisto, "params", return_value={"credential": {"password": "example"}}
    )
    mocker.patch.object(platform, "platform", return_value="mock_platform")
    mock_whoami = mocker.patch.object(IdentityRecordedFuture.Client, "whoami")
    mock_whoami.side_effect = Exception("Side effect triggered")
    mocked_return_err = mocker.patch.object(IdentityRecordedFuture, "return_error")
    IdentityRecordedFuture.main()

    mocked_return_err.assert_called_with(
        message=(
            f"Failed to execute {demisto.command()} command. Error: Failed due to - "
            "Unknown error. Please verify that the API URL and Token are correctly configured. "
            "RAW Error: Side effect triggered"
        ),
        error=mocker.ANY,
    )


@patch("IdentityRecordedFuture.demisto")
@patch("IdentityRecordedFuture.Client")
@patch("IdentityRecordedFuture.Actions")
def test_main_general(
    actions_mock: Mock,
    client_mock: Mock,
    mocked_demisto: Mock,
):
    """Test main function if it runs correctly and calls general functions"""
    import IdentityRecordedFuture

    # Mocking a known command to ensure that the 'else' block is not triggered
    mocked_demisto.command.return_value = "test-module"
    mocked_demisto.params.return_value = {
        "server_url": "https://example.com",
        "credential": {"password": "example"},
    }

    IdentityRecordedFuture.main()

    client_mock.assert_called_once()
    mocked_demisto.params.assert_called_once_with()
    mocked_demisto.command.assert_called_once_with()
    actions_mock.assert_called_once_with(client_mock.return_value)


def test_main_with_unknown_command(mocker):
    """Test main function with an unknown command."""
    import demistomock as demisto
    import IdentityRecordedFuture

    mocker.patch.object(demisto, "command", return_value="unknown-command")
    mock_return_error = mocker.patch("IdentityRecordedFuture.return_error")
    mock_get_client = mocker.patch("IdentityRecordedFuture.get_client")

    IdentityRecordedFuture.main()

    mock_get_client.assert_called_once()
    mock_return_error.assert_called_once_with(
        message="Unknown command: unknown-command"
    )


def test_main_exception_handling(mocker):
    """Test main function's exception handling."""
    import demistomock as demisto
    import IdentityRecordedFuture

    mocker.patch.object(demisto, "command", return_value="test-module")
    mock_get_client = mocker.patch("IdentityRecordedFuture.get_client")
    mock_get_client.return_value.whoami.side_effect = Exception("Test exception")
    mock_return_error = mocker.patch("IdentityRecordedFuture.return_error")

    IdentityRecordedFuture.main()

    mock_get_client.assert_called_once()
    mock_return_error.assert_called_once_with(
        message=(
            "Failed to execute test-module command. Error: Failed due to - Unknown error. "
            "Please verify that the API URL and Token are correctly configured. RAW Error: Test exception"
        ),
        error=mocker.ANY,
    )


def test_get_client_no_api_token(mocker):
    """Test get_client when no API token is provided."""
    import demistomock as demisto
    import IdentityRecordedFuture

    mock_params = {
        "server_url": "https://api.recordedfuture.com/gw/xsoar-identity/",
        "unsecure": False,
        "credential": {"password": None},
        "token": None,
    }
    mocker.patch.object(demisto, "params", return_value=mock_params)
    mock_return_error = mocker.patch("IdentityRecordedFuture.return_error")

    proxies = {}
    IdentityRecordedFuture.get_client(proxies=proxies)

    mock_return_error.assert_called_once_with(
        message="Please provide a valid API token"
    )


@patch("IdentityRecordedFuture.Client")
def test_get_client_with_proxy(client_mock, mocker):
    """Test get_client when proxy is used."""
    import demistomock as demisto
    import IdentityRecordedFuture

    server_url = "https://api.recordedfuture.com/gw/xsoar-identity/"

    unsecure = False
    verify_ssl = not unsecure

    mock_params = {
        "server_url": server_url,
        "unsecure": unsecure,
        "credential": {"password": "example"},
        "proxy": True,
    }
    mocker.patch.object(demisto, "params", return_value=mock_params)

    proxies = {"http": "example.com", "https": "example.com"}
    IdentityRecordedFuture.get_client(proxies=proxies)

    client_mock.assert_called_once_with(
        base_url=server_url.rstrip("/"),
        verify=verify_ssl,
        headers=mocker.ANY,
        proxy=bool(proxies),
    )


@patch("IdentityRecordedFuture.Client")
def test_get_client_without_proxy(client_mock, mocker):
    """Test get_client when proxy is not used."""
    import demistomock as demisto
    import IdentityRecordedFuture

    server_url = "https://api.recordedfuture.com/gw/xsoar-identity/"

    unsecure = False
    verify_ssl = not unsecure

    mock_params = {
        "server_url": server_url,
        "unsecure": unsecure,
        "credential": {"password": "example"},
        "proxy": False,
    }
    mocker.patch.object(demisto, "params", return_value=mock_params)

    proxies = {}
    IdentityRecordedFuture.get_client(proxies=proxies)

    client_mock.assert_called_once_with(
        base_url=server_url.rstrip("/"),
        verify=verify_ssl,
        headers=mocker.ANY,
        proxy=bool(proxies),
    )


def test_main_calls_handle_proxy(mocker):
    """
    Test main function to ensure it calls handle_proxy() and provides proxies to the get_client.
    """
    import demistomock as demisto
    import IdentityRecordedFuture

    mock_proxies = {"http": "example.com", "https": "example.com"}
    mock_handle_proxy = mocker.patch(
        "IdentityRecordedFuture.handle_proxy", return_value=mock_proxies
    )

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(
        demisto, "params", return_value={"credential": {"password": "example"}}
    )
    mock_get_client = mocker.patch("IdentityRecordedFuture.get_client")
    mocker.patch("IdentityRecordedFuture.Client.whoami")
    mock_return_results = mocker.patch("IdentityRecordedFuture.return_results")

    IdentityRecordedFuture.main()

    mock_handle_proxy.assert_called_once()

    mock_get_client.assert_called_once_with(proxies=mock_proxies)

    mock_return_results.assert_called_once_with("ok")

import pytest
from CommonServerPython import CommandResults
from FeedOpenCTI_v4 import *
from pycti import StixCyberObservable
from test_data.feed_data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS


class Client:
    temp = ""
    stix_cyber_observable = StixCyberObservable


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - `fetch_indicators_command` or `get_indicators_command` are calling the get_indicators function
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    _, indicators = get_indicators(client, indicator_types=["registry key", "account"], limit=10)
    assert len(indicators) == 2


def test_get_indicators__filters(mocker):
    """Tests get_indicators function filters
    Given
        The following: indicator types: 'registry key', 'account', score: [1, 2].
    When
        -  the get_indicators function is called
    Then
        - validate the filters that are sent to the API are correct.

    """
    client = Client
    mock_request = mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    _, indicators = get_indicators(client, indicator_types=["registry key", "account"], score=[1, 2], limit=10)
    assert mock_request.call_args[1]["filters"] == {
        "mode": "and",
        "filters": [
            {"key": "entity_type", "values": ["Windows-Registry-Key", "User-Account"], "operator": "eq", "mode": "or"},
            {"key": "x_opencti_score", "values": [1, 2], "operator": "eq", "mode": "or"},
        ],
        "filterGroups": [],
    }


def test_fetch_indicators_command(mocker):
    """Tests fetch_indicators_command function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - Calling `fetch_indicators_command`
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    indicators = fetch_indicators_command(client, indicator_types=["registry key", "account"], max_fetch=200)
    assert len(indicators) == 2


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user and 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {"indicator_types": "registry key,account", "limit": 2}
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators" in results.readable_output


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - Calling `get_indicators_command`
    Then
        - validate the response to have a "No indicators" string
    """
    client = Client
    args = {"indicator_types": ["registry key", "account"]}
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_WITHOUT_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert "No indicators" in results.readable_output


def test_get_indicators__deterministic_ordering(mocker):
    """
    Given
        - A stored pagination cursor.
    When
        - Calling get_indicators.
    Then
        - Validate the API is called with explicit orderBy/orderMode so cursor pagination is stable.
    """
    client = Client
    mock_request = mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    get_indicators(client, indicator_types=["ALL"], limit=10, last_run_id="cursor")
    call_kwargs = mock_request.call_args[1]
    assert call_kwargs["orderBy"] == "created_at"
    assert call_kwargs["orderMode"] == "asc"
    assert call_kwargs["after"] == "cursor"
    assert call_kwargs["withPagination"] is True


def test_get_indicators__pagination_error_raises_detailed_error(mocker):
    """
    Given
        - OpenCTI fails with a DATABASE_ERROR pagination error for a stored cursor.
    When
        - Calling get_indicators.
    Then
        - Validate a DemistoException is raised with the original error, the cursor and remediation guidance.
    """
    client = Client
    mocker.patch.object(
        client.stix_cyber_observable,
        "list",
        side_effect=ValueError("[{'name': 'DATABASE_ERROR', 'error_message': 'Fail to execute engine pagination'}]"),
    )
    with pytest.raises(DemistoException) as e:
        get_indicators(client, indicator_types=["ALL"], limit=10, last_run_id="stale_cursor")
    message = str(e.value)
    assert "Fail to execute engine pagination" in message
    assert "stale_cursor" in message
    assert "!opencti-reset-fetch-indicators" in message


def test_get_indicators__empty_response_raises(mocker):
    """
    Given
        - OpenCTI returns an empty response (None).
    When
        - Calling get_indicators.
    Then
        - Validate a DemistoException is raised instead of an AttributeError.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=None)
    with pytest.raises(DemistoException, match="empty response"):
        get_indicators(client, indicator_types=["ALL"], limit=10)


def test_fetch_indicators_command__error_keeps_last_run(mocker):
    """
    Given
        - A stored cursor and an API failure.
    When
        - Calling fetch_indicators_command.
    Then
        - Validate the error is propagated and the integration context is not modified.
    """
    client = Client
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"last_run_id": "cursor", "order_by": "created_at"})
    set_context = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(client.stix_cyber_observable, "list", side_effect=Exception("DATABASE_ERROR"))
    with pytest.raises(DemistoException, match="DATABASE_ERROR"):
        fetch_indicators_command(client, indicator_types=["ALL"], max_fetch=10)
    set_context.assert_not_called()


def test_fetch_indicators_command__saves_cursor_with_ordering(mocker):
    """
    Given
        - A stored cursor that was created with the current ordering.
    When
        - Calling fetch_indicators_command.
    Then
        - Validate the stored cursor is sent and the new cursor is saved together with the ordering marker.
    """
    client = Client
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"last_run_id": "cursor", "order_by": "created_at"})
    set_context = mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "createIndicators")
    mock_request = mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    fetch_indicators_command(client, indicator_types=["ALL"], max_fetch=10)
    assert mock_request.call_args[1]["after"] == "cursor"
    set_context.assert_called_once_with({"last_run_id": RESPONSE_DATA["pagination"]["endCursor"], "order_by": "created_at"})


def test_fetch_indicators_command__ignores_legacy_cursor(mocker):
    """
    Given
        - A cursor saved by a previous version (no ordering marker), which is incompatible with the new ordering.
    When
        - Calling fetch_indicators_command.
    Then
        - Validate fetching restarts from the first page instead of sending the legacy cursor.
    """
    client = Client
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"last_run_id": "legacy_cursor"})
    mocker.patch.object(demisto, "setIntegrationContext")
    mocker.patch.object(demisto, "createIndicators")
    mock_request = mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA)
    fetch_indicators_command(client, indicator_types=["ALL"], max_fetch=10)
    assert mock_request.call_args[1]["after"] is None

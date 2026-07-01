from datetime import datetime
from CommonServerPython import *
import pytest


@pytest.mark.parametrize(
    "time, expected_results",
    [
        (datetime(2024, 8, 14, 22, 43, 9, 851000), "2024-08-14 22:43:09.85"),
        (datetime(2024, 8, 14, 22, 43, 9), "2024-08-14 22:43:09.00"),
    ],
)
def test_convert_datetime_to_string(mocker, time, expected_results):
    """
    Given:
    - A datetime object
    - Case 1: datetime with microseconds
    - Case 2: datetime without microseconds
    When:
    - Calling convert_datetime_to_string()
    Then:
    - Ensure the datetime is converted to a string in the expected format (only 2 numbers after the decimal point)
    """
    mocker.patch.object(demisto, "params", return_value={})
    from Packs.Snowflake.Integrations.Snowflake.Snowflake import convert_datetime_to_string

    results = convert_datetime_to_string(time)
    assert results == expected_results


def test_fetch_incidents_passes_limit_key_to_snowflake_query(mocker):
    """
    Given:
    - A configured MAX_ROWS value of 1000
    When:
    - fetch_incidents() is called
    Then:
    - Ensure the args dict passed to snowflake_query contains the key "limit" (not "rows")
      with the configured MAX_ROWS value
    """
    mocker.patch.object(demisto, "params", return_value={"limit": "1000"})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import fetch_incidents

    mock_query = mocker.patch(
        "Packs.Snowflake.Integrations.Snowflake.Snowflake.snowflake_query",
        return_value=([], []),
    )

    fetch_incidents()

    called_args = mock_query.call_args[0][0]
    assert "limit" in called_args, "fetch_incidents should pass 'limit' key, not 'rows'"
    assert "rows" not in called_args, "fetch_incidents should not pass 'rows' key"
    assert called_args["limit"] == 1000


def test_snowflake_query_uses_provided_limit(mocker):
    """
    Given:
    - args dict with limit set to 500
    When:
    - snowflake_query() is called
    Then:
    - Ensure fetchmany is called with the provided limit value (500)
    """
    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import snowflake_query

    mock_cursor = mocker.MagicMock()
    mock_cursor.fetchmany.return_value = [{"col1": "val1"}]
    mock_cursor.description = [("col1", 2, None, None, None, None, None)]
    mock_cursor.__enter__ = mocker.MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = mocker.MagicMock(return_value=False)

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor
    mock_connection.__enter__ = mocker.MagicMock(return_value=mock_connection)
    mock_connection.__exit__ = mocker.MagicMock(return_value=False)

    mocker.patch("snowflake.connector.connect", return_value=mock_connection)

    args = {"limit": "500", "query": "SELECT 1"}
    snowflake_query(args)

    mock_cursor.fetchmany.assert_called_once_with(500)


def test_snowflake_query_defaults_to_100_when_no_limit(mocker):
    """
    Given:
    - args dict without a limit key
    When:
    - snowflake_query() is called
    Then:
    - Ensure fetchmany is called with the default value of 100
    """
    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import snowflake_query

    mock_cursor = mocker.MagicMock()
    mock_cursor.fetchmany.return_value = [{"col1": "val1"}]
    mock_cursor.description = [("col1", 2, None, None, None, None, None)]
    mock_cursor.__enter__ = mocker.MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = mocker.MagicMock(return_value=False)

    mock_connection = mocker.MagicMock()
    mock_connection.cursor.return_value = mock_cursor
    mock_connection.__enter__ = mocker.MagicMock(return_value=mock_connection)
    mock_connection.__exit__ = mocker.MagicMock(return_value=False)

    mocker.patch("snowflake.connector.connect", return_value=mock_connection)

    args = {"query": "SELECT 1"}
    snowflake_query(args)

    mock_cursor.fetchmany.assert_called_once_with(100)

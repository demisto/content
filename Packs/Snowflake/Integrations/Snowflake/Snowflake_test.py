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


@pytest.mark.parametrize(
    "raw_scope, expected",
    [
        ("scope1,scope2,scope3", "scope1 scope2 scope3"),
        ("session:role:analyst,   session:role:reader", "session:role:analyst session:role:reader"),
        ("scope1, scope2 , scope3", "scope1 scope2 scope3"),
        ("", None),
        (None, None),
        (",,,", None),
        ("scope1,,scope2", "scope1 scope2"),
    ],
)
def test_parse_oauth_scope(mocker, raw_scope, expected):
    """
    Given:
    - A raw OAuth scope string (comma-separated or single)
    - Case 1: Multiple scopes comma-separated
    - Case 2: Single scope
    - Case 3: Multiple scopes with extra whitespace
    - Case 4: Empty string
    - Case 5: None value
    - Case 6: Only commas
    - Case 7: Scopes with empty entries between commas
    When:
    - Calling parse_oauth_scope()
    Then:
    - Ensure the scopes are converted to space-separated format, or None for empty input
    """
    mocker.patch.object(demisto, "params", return_value={})
    from Packs.Snowflake.Integrations.Snowflake.Snowflake import parse_oauth_scope

    result = parse_oauth_scope(raw_scope)
    assert result == expected


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
    mocker.patch.object(demisto, "params", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "incidents")

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "FETCH_TIME", "3 days")
    mocker.patch.object(snowflake_module, "FETCH_QUERY", "SELECT * FROM test")
    mocker.patch.object(snowflake_module, "DATETIME_COLUMN", "TS")
    mocker.patch.object(snowflake_module, "MAX_ROWS", 1000)

    mock_query = mocker.patch(
        "Packs.Snowflake.Integrations.Snowflake.Snowflake.snowflake_query",
        return_value=([], []),
    )

    snowflake_module.fetch_incidents()

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

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "MAX_ROWS", 10000)
    mocker.patch.object(snowflake_module, "USER", "test_user")
    mocker.patch.object(snowflake_module, "PASSWORD", "test_password")
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

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "MAX_ROWS", 10000)
    mocker.patch.object(snowflake_module, "USER", "test_user")
    mocker.patch.object(snowflake_module, "PASSWORD", "test_password")
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


def test_get_connection_params_raises_when_no_auth(mocker):
    """
    Given:
    - No authentication method configured (no password, certificate, or OAuth)
    When:
    - get_connection_params() is called
    Then:
    - Ensure a ValueError is raised indicating no auth method configured
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "PASSWORD", None)
    mocker.patch.object(snowflake_module, "CERTIFICATE", b"")
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_ID", None)
    mocker.patch.object(snowflake_module, "OAUTH_TOKEN_URL", None)
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_SECRET", None)
    mocker.patch.object(snowflake_module, "OAUTH_SCOPE", None)

    with pytest.raises(ValueError, match="No authentication method configured"):
        snowflake_module.get_connection_params({})


def test_get_connection_params_raises_when_no_user(mocker):
    """
    Given:
    - A password is configured but no username
    When:
    - get_connection_params() is called
    Then:
    - Ensure a ValueError is raised indicating username is required
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "PASSWORD", "test_password")
    mocker.patch.object(snowflake_module, "USER", None)

    with pytest.raises(ValueError, match="Username is required"):
        snowflake_module.get_connection_params({})


def test_get_connection_params_password_auth(mocker):
    """
    Given:
    - Username and password are configured
    When:
    - get_connection_params() is called
    Then:
    - Ensure the returned params contain the user and password
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "USER", "test_user")
    mocker.patch.object(snowflake_module, "PASSWORD", "test_password")
    mocker.patch.object(snowflake_module, "CERTIFICATE", b"")
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_ID", None)
    mocker.patch.object(snowflake_module, "OAUTH_TOKEN_URL", None)
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_SECRET", None)
    mocker.patch.object(snowflake_module, "OAUTH_SCOPE", None)

    params = snowflake_module.get_connection_params({})

    assert params["user"] == "test_user"
    assert params["password"] == "test_password"


def test_get_connection_params_oauth(mocker):
    """
    Given:
    - OAuth client id, secret and token url are configured
    When:
    - get_connection_params() is called
    Then:
    - Ensure the returned params use OAUTH_CLIENT_CREDENTIALS authenticator and OAuth values
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "USER", "test_user")
    mocker.patch.object(snowflake_module, "PASSWORD", None)
    mocker.patch.object(snowflake_module, "CERTIFICATE", b"")
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_ID", "client_id")
    mocker.patch.object(snowflake_module, "OAUTH_TOKEN_URL", "https://token.url")
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_SECRET", "client_secret")
    mocker.patch.object(snowflake_module, "OAUTH_SCOPE", "scope1 scope2")

    params = snowflake_module.get_connection_params({})

    assert params["authenticator"] == "OAUTH_CLIENT_CREDENTIALS"
    assert params["oauth_client_id"] == "client_id"
    assert params["oauth_client_secret"] == "client_secret"
    assert params["oauth_token_request_url"] == "https://token.url"
    assert params["oauth_scope"] == "scope1 scope2"


def test_get_connection_params_oauth_missing_fields(mocker):
    """
    Given:
    - OAuth client id is set but token url and secret are missing
    When:
    - get_connection_params() is called
    Then:
    - Ensure a ValueError is raised indicating all OAuth fields are required
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "USER", "test_user")
    mocker.patch.object(snowflake_module, "PASSWORD", None)
    mocker.patch.object(snowflake_module, "CERTIFICATE", b"")
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_ID", "client_id")
    mocker.patch.object(snowflake_module, "OAUTH_TOKEN_URL", None)
    mocker.patch.object(snowflake_module, "OAUTH_CLIENT_SECRET", None)
    mocker.patch.object(snowflake_module, "OAUTH_SCOPE", None)

    with pytest.raises(ValueError, match="OAuth Client ID, Client Secret, and Token URL"):
        snowflake_module.get_connection_params({})


def test_set_provided(mocker):
    """
    Given:
    - Various combinations of val1 and val2
    When:
    - set_provided() is called
    Then:
    - Ensure the correct value is set (val1 preferred, val2 fallback, nothing if both empty)
    """
    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import set_provided

    params: dict = {}
    set_provided(params, "key1", "value1")
    set_provided(params, "key2", None, "fallback")
    set_provided(params, "key3", None, None)

    assert params["key1"] == "value1"
    assert params["key2"] == "fallback"
    assert "key3" not in params


def test_process_table_row(mocker):
    """
    Given:
    - A row with a Decimal value and a datetime value plus the corresponding checks
    When:
    - process_table_row() is called
    Then:
    - Ensure Decimal is converted to string and datetime is converted to a formatted string
    """
    from decimal import Decimal

    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import process_table_row

    row = {"num": Decimal("10.5"), "ts": datetime(2024, 8, 14, 22, 43, 9), "other": "text"}
    checks = {"isDecimal": ["num"], "isDT": ["ts"]}

    result = process_table_row(row, checks)

    assert result["num"] == "10.5"
    assert result["ts"] == "2024-08-14 22:43:09.00"
    assert result["other"] == "text"


def test_format_to_json_serializable(mocker):
    """
    Given:
    - Column descriptions with number/int and timestamp type codes and a list of rows
    When:
    - format_to_json_serializable() is called
    Then:
    - Ensure the Decimal and datetime values are reformatted to json serializable types
    """
    from decimal import Decimal

    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import format_to_json_serializable

    column_descriptions = [
        ("num", 0, None, None, None, None, None),
        ("ts", 4, None, None, None, None, None),
    ]
    results = [{"num": Decimal("3.14"), "ts": datetime(2024, 8, 14, 22, 43, 9)}]

    formatted = format_to_json_serializable(column_descriptions, results)

    assert formatted[0]["num"] == "3.14"
    assert formatted[0]["ts"] == "2024-08-14 22:43:09.00"


def test_error_message_from_snowflake_error(mocker):
    """
    Given:
    - A snowflake error-like object with errno 606
    When:
    - error_message_from_snowflake_error() is called
    Then:
    - Ensure a formatted error message that mentions specifying an active warehouse is returned
    """
    mocker.patch.object(demisto, "params", return_value={})

    from Packs.Snowflake.Integrations.Snowflake.Snowflake import error_message_from_snowflake_error

    class FakeError:
        errno = 606
        sqlstate = "00000"
        sfqid = "abc-123"
        raw_msg = "No active warehouse. Additional info."

    result = error_message_from_snowflake_error(FakeError())

    assert "Snowflake DB error code: 606" in result
    assert "Specify an active warehouse" in result


def test_row_to_incident(mocker):
    """
    Given:
    - Column descriptions and a row containing a datetime column
    When:
    - row_to_incident() is called
    Then:
    - Ensure an incident dict with name, occurred, timestamp and rawJSON is returned
    """
    mocker.patch.object(demisto, "params", return_value={})

    import Packs.Snowflake.Integrations.Snowflake.Snowflake as snowflake_module

    mocker.patch.object(snowflake_module, "DATETIME_COLUMN", "TS")
    mocker.patch.object(snowflake_module, "INCIDENT_NAME_COLUMN", "NAME")

    column_descriptions = [("TS", 4, None, None, None, None, None)]
    row = {"TS": datetime(2024, 8, 14, 22, 43, 9), "NAME": "my-incident"}

    incident = snowflake_module.row_to_incident(column_descriptions, row)

    assert incident["name"] == "my-incident"
    assert "occurred" in incident
    assert "timestamp" in incident
    assert "rawJSON" in incident

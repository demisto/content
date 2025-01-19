import demistomock as demisto  # noqa: F401
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


def test_convert_event_severity():
    """
    Given:
     - A severity integer (0, 1, 2, 3).
    When:
     - Calling the convert_event_severity function.
    Then:
     - Ensure the correct mapped severity is returned. If the severity is not recognized, return 0.
    """
    from GCenter103 import convert_event_severity

    assert convert_event_severity(0) == 0.5
    assert convert_event_severity(1) == 4
    assert convert_event_severity(2) == 2
    assert convert_event_severity(3) == 1
    # Test an unmapped severity
    assert convert_event_severity(999) == 0


def test_gw_client_auth_success():
    """
    Given:
     - A GwClient instance with username/password.
     - The server returns a 200 status code and a token in JSON.
    When:
     - The auth method is called.
    Then:
     - The client.headers dict should contain the 'API-KEY'.
    """
    from GCenter103 import GwClient

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"token": "testtoken"}

    with patch.object(GwClient, '_post', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        client.auth(user="test_user", password="test_pass")
        assert client.headers.get("API-KEY") == "testtoken"


def test_gw_client_auth_failure():
    """
    Given:
     - A GwClient instance with wrong credentials.
     - The server returns a non-200 status code.
    When:
     - The auth method is called.
    Then:
     - GwAPIException is raised due to failed authentication.
    """
    from GCenter103 import GwClient, GwAPIException

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.reason = "Unauthorized"
    mock_response.text = "Invalid credentials"

    with patch.object(GwClient, '_post', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        with pytest.raises(GwAPIException):
            client.auth(user="wrong_user", password="wrong_pass")


def test_gw_client_is_authenticated_true():
    """
    Given:
     - A GwClient instance that has valid session info.
     - The server's _get call returns status code 200.
    When:
     - is_authenticated is called.
    Then:
     - The function should return True.
    """
    from GCenter103 import GwClient

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch.object(GwClient, '_get', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        assert client.is_authenticated() is True


def test_gw_client_is_authenticated_false():
    """
    Given:
     - A GwClient instance that has invalid session info.
     - The server's _get call returns status code 404.
    When:
     - is_authenticated is called.
    Then:
     - The function should return False.
    """
    from GCenter103 import GwClient

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch.object(GwClient, '_get', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        assert client.is_authenticated() is False


def test_test_module_ok():
    """
    Given:
     - A GwClient instance that is properly authenticated.
     - is_authenticated returns True.
    When:
     - test_module is called.
    Then:
     - The function should return 'ok'.
    """
    from GCenter103 import GwClient, test_module

    mock_response = MagicMock()
    mock_response.status_code = 200

    with patch.object(GwClient, '_get', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        result = test_module(client)
        assert result == "ok"


def test_test_module_auth_error():
    """
    Given:
     - A GwClient instance that is not authenticated properly.
     - is_authenticated returns False.
    When:
     - test_module is called.
    Then:
     - The function should return the expected error string.
    """
    from GCenter103 import GwClient, test_module

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch.object(GwClient, '_get', return_value=mock_response):
        client = GwClient(ip="fake_ip")
        result = test_module(client)
        assert "Authentication error" in result


def test_last_run_range_no_last_run(mocker):
    """
    Given:
     - No previous last run data (demisto.getLastRun() returns an empty dict).
     - A 'first_fetch' param specifying an offset time, e.g., '1 day'.
    When:
     - last_run_range is called.
    Then:
     - It returns a list of two strings [start_time, end_time].
       The start_time is the computed 'first_fetch_dt', and the end_time is the current time.
    """
    from GCenter103 import last_run_range

    # 1) Patch demisto.getLastRun to return an empty dict (first fetch).
    mocker.patch.object(demisto, 'getLastRun', return_value={})

    # 2) Patch the datetime module in GCenter103 so that 'today()' returns a fixed date.
    fixed_now = datetime(2025, 1, 1, 10, 0, 0)
    mock_datetime = mocker.patch('GCenter103.datetime')
    mock_datetime.today.return_value = fixed_now
    mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

    # 3) Call the function under test.
    params = {'first_fetch': '1 day'}
    from_to = last_run_range(params=params)

    # 4) Basic assertions: we have a start time and an end time.
    assert len(from_to) == 2
    # The second element should contain our fixed timestamp "2025-01-01T10:00:00"
    assert "2025-01-01T10:00:00" in from_to[1]


def test_last_run_range_has_last_run(mocker):
    """
    Given:
     - A last run exists in demisto's context with a specific start_time.
    When:
     - last_run_range is called.
    Then:
     - It returns [last_start_time, now].
    """
    from GCenter103 import last_run_range

    # 1) Patch demisto.getLastRun to simulate an existing last run time.
    mocker.patch.object(demisto, 'getLastRun', return_value={'start_time': '2025-01-01T00:00:00Z'})

    # 2) Patch the datetime module to control the current time.
    fixed_now = datetime(2025, 1, 2, 12, 0, 0)
    mock_datetime = mocker.patch('GCenter103.datetime')
    mock_datetime.today.return_value = fixed_now
    mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

    # 3) Call the function under test.
    params = {'first_fetch': '1 day'}
    from_to = last_run_range(params=params)

    # 4) Validate that we get [stored_start_time, now].
    assert len(from_to) == 2
    assert from_to[0] == '2025-01-01T00:00:00Z'
    assert "2025-01-02T12:00:00" in from_to[1]
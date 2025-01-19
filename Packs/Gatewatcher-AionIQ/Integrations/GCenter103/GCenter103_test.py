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


def test_fix_broken_list_valid_str():
    """
    Given:
     - A valid 'engine_selection' string that contains known engine names.
    When:
     - fix_broken_list is called.
    Then:
     - Verify we only return known engines from the string.
    """
    from GCenter103 import fix_broken_list
    params = {
        'engine_selection': "malcore,shellcode_detect,unknown_engine"
    }
    result = fix_broken_list(params)
    # 'unknown_engine' should not appear
    assert "unknown_engine" not in result


def test_fix_broken_list_valid_list():
    """
    Given:
     - A valid 'engine_selection' list that contains known and unknown engine names.
    When:
     - fix_broken_list is called.
    Then:
     - Verify we only return known engines from the list.
    """
    from GCenter103 import fix_broken_list
    params = {
        'engine_selection': ["dga_detect", "ransomware_detect", "nonexistent"]
    }
    result = fix_broken_list(params)
    assert set(result) == {"dga_detect", "ransomware_detect"}, \
        f"Expected ['dga_detect','ransomware_detect'] but got {result}"


def test_fix_broken_list_invalid():
    """
    Given:
     - An invalid 'engine_selection' key or type in params (e.g., missing or not str/list).
    When:
     - fix_broken_list is called.
    Then:
     - A ValueError is raised.
    """
    from GCenter103 import fix_broken_list
    params = {
        'engine_selection': 12345  # Not a valid type
    }
    with pytest.raises(ValueError):
        fix_broken_list(params)


def test_gw_client_auth_token_only():
    """
    Given:
     - Params has a token but no user/password.
    When:
     - gw_client_auth is called.
    Then:
     - The client is created and its headers contain the API-KEY equal to the token.
    """
    from GCenter103 import gw_client_auth, GwClient

    with patch.object(GwClient, 'auth', return_value=None) as mock_auth:
        params = {
            "ip": "1.2.3.4",
            "token": "testtoken",
            "credentials": {"identifier": "", "password": ""}
        }
        client = gw_client_auth(params=params)
        mock_auth.assert_called_once()
        assert client.headers.get("API-KEY") == "testtoken"


def test_gw_client_auth_missing_all():
    """
    Given:
     - Params has no token, no user, no password.
    When:
     - gw_client_auth is called.
    Then:
     - We expect an AttributeError because user/password/token are all missing.
    """
    from GCenter103 import gw_client_auth
    params = {
        "ip": "1.2.3.4",
        "credentials": {"identifier": "", "password": ""},
        "token": None
    }
    with pytest.raises(AttributeError):
        gw_client_auth(params=params)


def test_index_alerts_incidents():
    """
    Given:
     - A list of alert hits from ES (to_index).
    When:
     - index_alerts_incidents is called.
    Then:
     - We return a properly structured list of incidents with correct fields.
    """
    from GCenter103 import index_alerts_incidents
    sample_hits = [
        {
            '_source': {
                'event': {
                    'id': 'alert123',
                    'module': 'malcore',
                    'severity': 1
                },
                'source': {'ip': '1.1.1.1'},
                'destination': {'ip': '2.2.2.2'},
                '@timestamp': '2025-01-01T12:00:00Z'
            },
            'sort': [9999]
        }
    ]
    incidents = []
    params = {'ip': '1.2.3.4'}
    # Run the function
    results = index_alerts_incidents(sample_hits, incidents, params)
    # Check that we have 1 incident with the correct fields
    assert len(results) == 1
    incident = results[0]
    assert incident['name'] == "Gatewatcher Alert: malcore"
    assert incident['occurred'] == "2025-01-01T12:00:00Z"
    assert incident['dbotMirrorId'] == "alert123"
    assert incident['severity'] == 4  # from convert_event_severity(1)
    assert incident['CustomFields']['GatewatcherRawEvent'] is not None


def test_index_metadata_incidents():
    """
    Given:
     - A list of metadata hits from ES (to_index).
    When:
     - index_metadata_incidents is called.
    Then:
     - We return a properly structured list of incidents with correct fields.
    """
    from GCenter103 import index_metadata_incidents

    sample_hits = [
        {
            '_source': {
                'event': {
                    'id': 'meta123',
                    'module': 'beacon_detect',
                    'severity': 0
                },
                'source': {'ip': '3.3.3.3'},
                'destination': {'ip': '4.4.4.4'},
                '@timestamp': '2025-01-02T12:00:00Z'
            },
            'sort': [1111]
        }
    ]
    incidents = []
    results = index_metadata_incidents(sample_hits, incidents)
    assert len(results) == 1
    incident = results[0]
    assert incident['name'] == "Gatewatcher Metadata: beacon_detect"
    assert incident['occurred'] == "2025-01-02T12:00:00Z"
    assert incident['dbotMirrorId'] == "meta123"
    assert incident['severity'] == 0.5  # from convert_event_severity(0)


def test_query_selected_engines_builder():
    """
    Given:
     - max_fetch, engine_selection, from_to range.
    When:
     - query_selected_engines_builder is called.
    Then:
     - The generated query includes 'match' for the first engine and a timestamp range.
    """
    from GCenter103 import query_selected_engines_builder

    engine_selection = ["malcore", "shellcode_detect"]
    from_to = ["2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z"]
    query = query_selected_engines_builder(max_fetch=5000,
                                           engine_selection=engine_selection,
                                           from_to=from_to)
    assert query["size"] == 5000
    assert query["query"]["bool"]["must"][0]["match"]["event.module"] == "malcore"
    assert query["query"]["bool"]["must"][1]["range"]["@timestamp"]["gt"] == "2025-01-01T00:00:00Z"


def test_query_empty_selected_engines_builder():
    """
    Given:
     - A from_to range and max_fetch.
    When:
     - query_empty_selected_engines_builder is called.
    Then:
     - The generated query doesn't contain a 'match' on 'event.module', only a time range.
    """
    from GCenter103 import query_empty_selected_engines_builder

    from_to = ["2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z"]
    query = query_empty_selected_engines_builder(from_to=from_to, max_fetch=9999)
    assert query["size"] == 9999
    assert "range" in query["query"]
    assert "@timestamp" in query["query"]["range"]
    assert "match" not in query["query"]


@pytest.mark.parametrize("engine_list,fetch_type,max_fetch", [
    (["malcore"], "Alerts", 5),
    (["malcore", "shellcode_detect"], "Both", 12000),
    ([], "Alerts", 5),  # Should go to fetch_empty_selected_engines
])
def test_fetch_incidents(mocker, engine_list, fetch_type, max_fetch):
    """
    Given:
     - Different engine_list setups (empty or not), different fetch_type, and different max_fetch.
    When:
     - fetch_incidents is called.
    Then:
     - The correct sub-function (fetch_selected_engines or fetch_empty_selected_engines) is invoked.
     - The final demisto.incidents(...) is called with a list of built incidents.
    """
    from GCenter103 import fetch_incidents, GwClient, demisto

    # Patch demisto methods using mocker.patch.object
    mocker.patch.object(
        demisto,
        'params',
        return_value={
            "ip": "1.2.3.4",
            "fetch_type": fetch_type,
            "max_fetch": max_fetch,
            "engine_selection": engine_list,
            "credentials": {"identifier": "", "password": ""},
            "token": "dummy_token"
        }
    )
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mock_set_last_run = mocker.patch.object(demisto, 'setLastRun')
    mock_incidents = mocker.patch.object(demisto, 'incidents')

    # Patch subfunctions within GCenter103
    mock_sel = mocker.patch(
        "GCenter103.fetch_selected_engines",
        return_value=[{"name": "TestIncidentSelected", "occurred": "2025-01-01T12:00:00Z"}]
    )
    mock_emp = mocker.patch(
        "GCenter103.fetch_empty_selected_engines",
        return_value=[{"name": "TestIncidentEmpty", "occurred": "2025-01-01T12:00:00Z"}]
    )
    mocker.patch(
        "GCenter103.gw_client_auth",
        return_value=MagicMock(spec=GwClient)
    )

    # Execute
    fetch_incidents()

    # Verify
    if engine_list:
        # We used fetch_selected_engines
        mock_sel.assert_called_once()
        mock_emp.assert_not_called()
        mock_incidents.assert_called_once_with(
            incidents=[{"name": "TestIncidentSelected", "occurred": "2025-01-01T12:00:00Z"}]
        )
    else:
        # We used fetch_empty_selected_engines
        mock_emp.assert_called_once()
        mock_sel.assert_not_called()
        mock_incidents.assert_called_once_with(
            incidents=[{"name": "TestIncidentEmpty", "occurred": "2025-01-01T12:00:00Z"}]
        )

    # In both scenarios, last run should be set
    mock_set_last_run.assert_called_once()

from CommonServerPython import *
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


@pytest.fixture
def mock_gw_client(mocker):
    """
    Fixture creating a mock GwClient instance with basic _post, _get stubs.
    """
    from GCenter103 import GwClient
    client = GwClient(ip="fake_ip")
    return client


def test_fix_broken_list_str(mocker):
    """
    Given:
     - A params dictionary with 'engine_selection' set to a string containing known engine keywords.
    When:
     - fix_broken_list is called.
    Then:
     - We get only the matching engines in a list.
    """
    from GCenter103 import fix_broken_list
    params = {"engine_selection": "malcore,random,sigflow_alert"}
    result = fix_broken_list(params)
    # Known engines are: "malcore", "sigflow_alert"
    assert len(result) == 2
    assert "malcore" in result
    assert "sigflow_alert" in result


def test_fix_broken_list_list(mocker):
    """
    Given:
     - A params dictionary with 'engine_selection' as a list containing known engine keywords.
    When:
     - fix_broken_list is called.
    Then:
     - We get only the valid engines from that list.
    """
    from GCenter103 import fix_broken_list
    params = {"engine_selection": ["malcore", "abc", "shellcode_detect"]}
    result = fix_broken_list(params)
    assert len(result) == 2
    assert "malcore" in result
    assert "shellcode_detect" in result


def test_fix_broken_list_invalid_param(mocker):
    """
    Given:
     - A params dictionary missing engine_selection or with invalid type.
    When:
     - fix_broken_list is called.
    Then:
     - A ValueError is raised.
    """
    from GCenter103 import fix_broken_list
    with pytest.raises(ValueError):
        fix_broken_list({"no_engine_selection": True})
    with pytest.raises(ValueError):
        fix_broken_list({"engine_selection": 123})  # not str or list


def test_query_es_alerts(mocker, mock_gw_client):
    """
    Given:
     - A GwClient and a query dict.
    When:
     - query_es_alerts is called and the response has hits.hits data.
    Then:
     - The function returns hits.hits from the JSON response.
    """
    from GCenter103 import query_es_alerts

    mock_response = MagicMock(spec=requests.Response)
    mock_response.json.return_value = {"hits": {"hits": [{"_id": "1"}]}}
    mock_gw_client._post = MagicMock(return_value=mock_response)

    q = {"query": {"match_all": {}}}
    hits = query_es_alerts(mock_gw_client, q)
    assert hits == [{"_id": "1"}]


def test_query_es_alerts_empty(mocker, mock_gw_client):
    """
    Given:
     - A GwClient and a query dict.
    When:
     - query_es_alerts is called and hits.hits is empty.
    Then:
     - An empty dict is returned.
    """
    from GCenter103 import query_es_alerts

    mock_response = MagicMock(spec=requests.Response)
    mock_response.json.return_value = {"hits": {"hits": []}}
    mock_gw_client._post = MagicMock(return_value=mock_response)

    q = {"query": {"match_all": {}}}
    hits = query_es_alerts(mock_gw_client, q)
    assert hits == [{}]


def test_query_es_metadata(mocker, mock_gw_client):
    """
    Given:
     - A GwClient and a query dict.
    When:
     - query_es_metadata is called and the response has hits.hits data.
    Then:
     - The function returns hits.hits from the JSON response.
    """
    from GCenter103 import query_es_metadata

    mock_response = MagicMock(spec=requests.Response)
    mock_response.json.return_value = {"hits": {"hits": [{"_id": "m1"}]}}
    mock_gw_client._post = MagicMock(return_value=mock_response)

    q = {"query": {"match_all": {}}}
    hits = query_es_metadata(mock_gw_client, q)
    assert hits == [{"_id": "m1"}]


def test_gw_client_auth(mocker):
    """
    Given:
     - A params dict with user/password or token.
    When:
     - gw_client_auth is called.
    Then:
     - Returns a GwClient with the authentication set.
    """
    from GCenter103 import gw_client_auth
    mocker.patch('GCenter103.GwClient.auth', return_value=None)
    params = {
        "ip": "1.1.1.1",
        "token": None,
        "credentials": {"identifier": "admin", "password": "admin"},
        "check_cert": False
    }
    client = gw_client_auth(params)
    assert client.ip == "1.1.1.1"


def test_handle_little_fetch_empty_selected_engines_alerts(mocker, mock_gw_client):
    """
    Given:
     - fetch_type in ("Alerts", "Both").
     - query_es_alerts returning some hits.
    When:
     - handle_little_fetch_empty_selected_engines is called.
    Then:
     - The returned data is not empty (the alerts).
    """
    from GCenter103 import handle_little_fetch_empty_selected_engines

    mock_response = [{"_id": "abc"}]
    mocker.patch('GCenter103.query_es_alerts', return_value=mock_response)

    query = {"query": {"bool": {"must": []}}}
    res = handle_little_fetch_empty_selected_engines(mock_gw_client, "Alerts", query)
    assert res == mock_response


def test_handle_little_fetch_empty_selected_engines_not_alerts(mocker, mock_gw_client):
    """
    Given:
     - fetch_type = "Metadata" (no alerts).
     When:
     - handle_little_fetch_empty_selected_engines is called.
    Then:
     - The function returns an empty dict (no alerts fetched).
    """
    from GCenter103 import handle_little_fetch_empty_selected_engines
    query = {"query": {"bool": {"must": []}}}
    res = handle_little_fetch_empty_selected_engines(mock_gw_client, "Metadata", query)
    assert res == []  # no alerts if fetch_type == "Metadata"


def test_main_test_module(mocker):
    """
    Given:
     - demisto.command returns 'test-module'.
     - The client authenticates successfully.
    When:
     - main is called.
    Then:
     - test_module is executed, and 'ok' is returned as a result.
    """
    from GCenter103 import main

    # 1) Patch demisto commands/params
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'params', return_value={
        "ip": "1.1.1.1",
        "token": None,
        "credentials": {"identifier": "admin", "password": "admin"}
    })
    mocker.patch.object(demisto, 'args', return_value={})

    # 2) Patch `return_results` from the correct module path.
    mocked_return_results = mocker.patch('GCenter103.return_results')

    # 3) Mock GwClient so it doesn't do real auth
    client_mock = mocker.patch('GCenter103.GwClient', autospec=True).return_value
    client_mock.is_authenticated.return_value = True

    # 4) Run main
    main()

    # 5) Verify test_module returned "ok"
    mocked_return_results.assert_called_with("ok")


def test_main_fetch_incidents(mocker):
    """
    Given:
     - demisto.command returns 'fetch-incidents'.
    When:
     - main is called.
    Then:
     - fetch_incidents is invoked and passes a real list of incidents to return_results.
    """
    from GCenter103 import main

    # 1) Patch demisto commands/params
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'params', return_value={
        "ip": "1.1.1.1",
        "fetch_type": "Alerts",
        "credentials": {"identifier": "admin", "password": "admin"}
    })
    mocker.patch.object(demisto, 'args', return_value={})

    # 2) Patch `return_results` from the correct module path.
    mocked_return_results = mocker.patch('GCenter103.return_results')

    # 3) Mock out GwClient so we don't do real auth
    mocker.patch('GCenter103.GwClient')

    # 4) Make `fetch_incidents` return a **real list** (not MagicMock)
    #    so JSON serialization won't fail.
    mock_incidents = [
        {"name": "test_incident",
         "occurred": "2025-01-01T00:00:00Z",
         "type": "Gatewatcher Incident"}
    ]
    mocker.patch('GCenter103.fetch_incidents', return_value=mock_incidents)

    # 5) Execute main
    main()

    # 6) Confirm return_results was called with that real list
    #    (The actual call structure is [mock_incidents], but
    #     mocker captures the first positional arg from call_args[0]).
    called_arg = mocked_return_results.call_args[0][0]
    assert called_arg == mock_incidents


def test_handle_big_fetch_selected_engines_alerts(mocker):
    """
    Given:
     - fetch_type = "Alerts".
     - engine_selection has multiple engines (e.g., ["engineA", "engineB"]).
     - query_es_alerts returns chunks of alerts, each with a 'sort' key.
     - max_fetch is large enough to trigger multiple while-loop iterations.
    When:
     - handle_big_fetch_selected_engines is called.
    Then:
     - All fetched alerts from multiple engines are combined and returned.
     - search_after is updated repeatedly in the query.
    """
    from GCenter103 import handle_big_fetch_selected_engines

    mock_client = MagicMock()

    def mock_query_es_alerts_side_effect(*args, **kwargs):
        query = kwargs.get("query", {})
        # Distinguish the first chunk from the second chunk by checking
        # if 'search_after' is in the query
        if "search_after" not in query:
            # first chunk
            return [
                {'sort': [100], '_source': {"event": {"id": "id1"}}},
                {'sort': [101], '_source': {"event": {"id": "id2"}}}
            ]
        else:
            # second chunk
            return [
                {'sort': [200], '_source': {"event": {"id": "id3"}}},
                {'sort': [201], '_source': {"event": {"id": "id4"}}}
            ]

    mocker.patch('GCenter103.query_es_alerts', side_effect=mock_query_es_alerts_side_effect)

    initial_query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.module": "engineA"}},
                    {"range": {"@timestamp": {"gt": "2025-01-01"}}}
                ]
            }
        }
    }
    engine_selection = ["engineA", "engineB"]
    max_fetch = 1  # Ensure nb_req=0 => nb_req=1 => 1 iteration => 2 calls total/engine
    fetch_type = "Alerts"

    results = handle_big_fetch_selected_engines(
        client=mock_client,
        query=initial_query,
        engine_selection=engine_selection,
        max_fetch=max_fetch,
        fetch_type=fetch_type
    )

    # Each engine => 4 total items (2 per call * 2 calls).
    # We have 2 engines => 8 total.
    assert len(results) == 8
    # Confirm query had 'size' set to 10000
    assert initial_query["size"] == 10000
    # Confirm each chunk's 'search_after' was updated in the while loop
    # The final value should have been reset to [] after engineB is processed.
    assert "search_after" in initial_query
    assert initial_query["search_after"] == []


def test_handle_big_fetch_selected_engines_no_alerts(mocker):
    """
    Given:
     - fetch_type = "Metadata" (the code *still* fetches alerts in the for-loop).
    When:
     - handle_big_fetch_selected_engines is called.
    Then:
     - We confirm that calls to query_es_alerts return our dummy item,
       and the final list matches it, e.g. 4 items if we have 2 engines.
    """
    from GCenter103 import handle_big_fetch_selected_engines

    mock_client = MagicMock()

    def mock_query_es_alerts_side_effect(*args, **kwargs):
        return [{'_source': {"event": {"id": "dummy"}}, 'sort': [999]}]

    mocker.patch('GCenter103.query_es_alerts', side_effect=mock_query_es_alerts_side_effect)

    # Correctly define query_mock as a dict with the structure your code expects
    query_mock = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"match": {"event.module": "engineA"}},
                    {"range": {"@timestamp": {"gt": "2025-01-01"}}}
                ]
            }
        }
    }
    engine_selection = ["engineA", "engineB"]
    max_fetch = 20000
    fetch_type = "Metadata"

    results = handle_big_fetch_selected_engines(
        client=mock_client,
        query=query_mock,
        engine_selection=engine_selection,
        max_fetch=max_fetch,
        fetch_type=fetch_type
    )
    assert len(results) == 4


@pytest.mark.parametrize(
    "max_fetch_val, fetch_type_val, returned_alerts, returned_metadata",
    [
        # 1) Big fetch scenario (max_fetch > 10000), "Both" => calls big-fetch logic for both alerts+metadata
        (15000, "Both", [{"_source": {"event": {"id": "alert1"}}}], [{"_source": {"event": {"id": "meta1"}}}]),
        # 2) Small fetch scenario (max_fetch <= 10000), "Alerts" => calls little-fetch for alerts
        (5000, "Alerts", [{"_source": {"event": {"id": "alert2"}}}], []),
        # 3) Another small fetch scenario with "Both"
        (5000, "Both", [{"_source": {"event": {"id": "alert3"}}}], [{"_source": {"event": {"id": "meta3"}}}])
    ]
)
def test_fetch_selected_engines(mocker, max_fetch_val, fetch_type_val, returned_alerts, returned_metadata):
    """
    Given:
     - A non-empty engine_selection.
     - max_fetch can be above or below 10000.
     - Different fetch_type ("Alerts", "Both", etc.).
    When:
     - fetch_selected_engines is called.
    Then:
     - The correct big or little fetch helper is used, and the results are combined with indexing.
    """
    from GCenter103 import (
        fetch_selected_engines
    )

    # 1) Patch last_run_range to avoid real datetime calls
    mocker.patch('GCenter103.last_run_range', return_value=["2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z"])

    # 2) Patch the big fetch or little fetch calls
    mock_handle_big_fetch_selected_engines = mocker.patch(
        'GCenter103.handle_big_fetch_selected_engines', return_value=returned_alerts
    )
    mock_handle_big_fetch_metadata = mocker.patch('GCenter103.handle_big_fetch_metadata', return_value=returned_metadata)

    mock_handle_little_fetch_alerts = mocker.patch('GCenter103.handle_little_fetch_alerts', return_value=returned_alerts)
    mock_handle_little_fetch_metadata = mocker.patch('GCenter103.handle_little_fetch_metadata', return_value=returned_metadata)

    # 3) Patch index functions to simply return the incidents back
    def mock_index_alerts_incidents(to_index, incidents, params):
        # Just append them with a placeholder structure
        for item in to_index:
            incidents.append({"name": "Alert: " + str(item["_source"]["event"]["id"]), "occurred": "2025-01-01T00:00:00Z"})
        return incidents

    def mock_index_metadata_incidents(to_index, incidents):
        for item in to_index:
            incidents.append({"name": "Meta: " + str(item["_source"]["event"]["id"]), "occurred": "2025-01-02T00:00:00Z"})
        return incidents

    mocker.patch('GCenter103.index_alerts_incidents', side_effect=mock_index_alerts_incidents)
    mocker.patch('GCenter103.index_metadata_incidents', side_effect=mock_index_metadata_incidents)

    mock_client = MagicMock()  # pretend we have a real client
    engine_selection = ["suricata"]
    params = {"ip": "1.1.1.1"}  # minimal for test
    incidents = []

    # 4) Call function under test
    results = fetch_selected_engines(
        client=mock_client,
        engine_selection=engine_selection,
        params=params,
        max_fetch=max_fetch_val,
        fetch_type=fetch_type_val,
        incidents=incidents
    )

    # 5) Then: check logic paths
    if max_fetch_val > 10000:
        # big fetch
        mock_handle_big_fetch_selected_engines.assert_called_once()
        if fetch_type_val in ("Both", "Alerts"):
            # We should see calls to big fetch for alerts
            mock_handle_big_fetch_metadata.assert_called_once()
        else:
            mock_handle_big_fetch_metadata.assert_not_called()
        mock_handle_little_fetch_alerts.assert_not_called()
        mock_handle_little_fetch_metadata.assert_not_called()
    else:
        # little fetch
        mock_handle_little_fetch_alerts.assert_called_once()
        if fetch_type_val in ("Both", "Alerts"):
            mock_handle_little_fetch_alerts.assert_called_once()
        if fetch_type_val in ("Both", "Metadata"):
            mock_handle_little_fetch_metadata.assert_called_once()
        mock_handle_big_fetch_selected_engines.assert_not_called()
        mock_handle_big_fetch_metadata.assert_not_called()

    # Also verify the final incidents list structure
    if returned_alerts:
        assert any("Alert: " in inc["name"] for inc in results)
    if returned_metadata:
        assert any("Meta: " in inc["name"] for inc in results)
    # If we get no alerts or metadata, results is empty


def test_gcenter103_alerts_get(mocker):
    """
    When:
        gcenter103-alerts-get is called with an alert UUID.
    Returns:
        The alert found.
    """
    from GCenter103 import(
        gcenter103_alerts_get_command
    )
    raw_alerts_get_response = util_load_json('test_data/raw_alerts_get_response.json')
    client = mock_gw_client(mocker)
    res = gcenter103_alerts_get_command(client=client, args={'uuid': "1be3530b-2e94-4a89-b57f-6fb9f39e1b54"})
    assert res.get('dest_ip') == "27.0.0.118"

import json

import pytest
from CommonServerPython import DemistoException, GetModifiedRemoteDataResponse

from GoogleThreatIntelligenceRSAlerts import (
    RS_CLOSE_REASON_MAPPING,
    RS_CLOSE_STATUSES,
    RS_OPEN_STATUSES,
    RS_SEVERITY_TO_XSOAR_SEVERITY,
    RS_STATE_TO_XSOAR_STATE,
    RS_UPDATE_STATUS_API_MAP,
    RS_UPDATE_STATUS_HR_LIST,
    AUTH_BASE_URL,
    BASE_URL,
    ENDPOINTS,
    ERROR_MESSAGES,
    MAX_FETCH,
    MAX_MIRRORING_LIMIT,
    MIRROR_DIRECTION,
    Client,
    OUTPUT_PREFIX,
)


def util_load_json(path):
    """Load JSON data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker, requests_mock):
    """Create a mocked client for testing.

    Mocks the integration context as empty so the Client init triggers a
    token exchange against the auth endpoint, and stubs that endpoint to
    return a deterministic access token.
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=auth_response, status_code=200)

    return Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )


def test_client_uses_cached_access_token(mocker):
    """
    Given:
    - A previously cached access_token in the integration context.

    When:
    - Constructing the Client.

    Then:
    - The cached token is reused and no token-exchange request is made.
    """
    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "cached_token"},
    )
    set_context_mock = mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )

    assert client._token == "cached_token"
    set_context_mock.assert_not_called()


def test_client_generates_new_token_when_cache_empty(mocker, requests_mock):
    """
    Given:
    - An empty integration context.

    When:
    - Constructing the Client.

    Then:
    - The auth endpoint is invoked and the returned access_token is cached.
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    set_context_mock = mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=auth_response, status_code=200)

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )

    assert client._token == auth_response["access_token"]
    set_context_mock.assert_called_once_with({"access_token": auth_response["access_token"]})


def test_generate_token_invalid_api_key(mocker, requests_mock):
    """
    Given:
    - An empty integration context and an auth endpoint that returns 401.

    When:
    - Constructing the Client.

    Then:
    - A DemistoException is raised with the unauthorized error message.
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        json={"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}},
        status_code=401,
    )

    with pytest.raises(DemistoException) as exc:
        Client(
            server_url=BASE_URL,
            verify_certificate=False,
            proxy=False,
            api_key="bad_api_key",
            project_id="test_project",
        )

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_http_request_refreshes_token_on_401(mocker, requests_mock):
    """
    Given:
    - An authenticated client whose first call returns 401.

    When:
    - The Client retries the request.

    Then:
    - A new access token is generated and the retried call succeeds.
    """
    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "stale_token"},
    )
    set_context_mock = mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=auth_response, status_code=200)

    alert_list = util_load_json("test_data/alert_list.json")
    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(
        list_url,
        [
            {"json": {"error": "unauthorized"}, "status_code": 401},
            {"json": alert_list, "status_code": 200},
        ],
    )

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )

    response = client.get_alert_list(query_params={"pageSize": 1})

    assert response == alert_list
    assert client._token == auth_response["access_token"]
    set_context_mock.assert_called_with({"access_token": auth_response["access_token"]})


def test_test_module_success(mock_client, requests_mock):
    """
    Given:
    - A valid client.

    When:
    - test_module is invoked.

    Then:
    - The alert list endpoint is called and "ok" is returned.
    """
    from GoogleThreatIntelligenceRSAlerts import test_module

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json=util_load_json("test_data/alert_list.json"), status_code=200)

    assert test_module(client=mock_client) == "ok"


def test_test_module_invalid_api_key(mocker, requests_mock):
    """
    Given:
    - A client whose access token is treated as invalid by the alerts endpoint,
      and an auth endpoint that also rejects the API key on the refresh attempt.

    When:
    - test_module is invoked.

    Then:
    - A DemistoException is raised with the unauthorized error message.
    """
    from GoogleThreatIntelligenceRSAlerts import test_module

    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "stale_token"},
    )
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="bad_api_key",
        project_id="test_project",
    )

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json={"error": "unauthorized"}, status_code=401)
    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        json={"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}},
        status_code=401,
    )

    with pytest.raises(DemistoException) as exc:
        test_module(client=client)

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_main_test_module_success(mocker, requests_mock):
    """
    Given:
    - Valid configuration parameters and the test-module command.

    When:
    - main is invoked.

    Then:
    - return_results is called with "ok" and return_error is not called.
    """
    from GoogleThreatIntelligenceRSAlerts import main

    mock_params = {
        "server_url": BASE_URL,
        "credentials": {"password": "test_api_key"},
        "project_id": "test_project",
        "insecure": False,
        "proxy": False,
    }

    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "test-module"
    mock_demisto.args.return_value = {}
    mock_demisto.debug = mocker.Mock()

    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    mock_return_results = mocker.patch("GoogleThreatIntelligenceRSAlerts.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceRSAlerts.return_error")

    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        json=util_load_json("test_data/auth_token.json"),
        status_code=200,
    )
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}",
        json=util_load_json("test_data/alert_list.json"),
        status_code=200,
    )

    main()

    mock_return_results.assert_called_once_with("ok")
    mock_return_error.assert_not_called()


def test_main_unknown_command(mocker):
    """
    Given:
    - An unknown command.

    When:
    - main is invoked.

    Then:
    - return_error is called with a "not implemented" message.
    """
    from GoogleThreatIntelligenceRSAlerts import main

    mock_params = {
        "server_url": BASE_URL,
        "credentials": {"password": "test_api_key"},
        "project_id": "test_project",
        "insecure": False,
        "proxy": False,
    }

    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "unknown-command"
    mock_demisto.args.return_value = {}

    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "cached_token"},
    )
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    mock_return_results = mocker.patch("GoogleThreatIntelligenceRSAlerts.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceRSAlerts.return_error")

    main()

    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "Failed to execute unknown-command command" in error_message
    assert "Command unknown-command is not implemented" in error_message
    mock_return_results.assert_not_called()


def test_generate_token_401_non_json_body(mocker, requests_mock):
    """
    Given:
    - An auth endpoint that returns 401 with a plain-text (non-JSON) body.

    When:
    - Constructing the Client.

    Then:
    - A DemistoException is raised and the error message still contains the
      "Unauthorized request" notice (the ValueError fallback path is taken).
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        text="Unauthorized",
        status_code=401,
    )

    with pytest.raises(DemistoException) as exc:
        Client(
            server_url=BASE_URL,
            verify_certificate=False,
            proxy=False,
            api_key="bad_api_key",
            project_id="test_project",
        )

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_generate_token_non_json_success_response(mocker, requests_mock):
    """
    Given:
    - An auth endpoint that returns 200 with a plain-text (non-JSON) body.

    When:
    - Constructing the Client.

    Then:
    - A DemistoException is raised because the token response cannot be parsed.
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        text="not-a-json-response",
        status_code=200,
    )

    with pytest.raises(DemistoException) as exc:
        Client(
            server_url=BASE_URL,
            verify_certificate=False,
            proxy=False,
            api_key="test_api_key",
            project_id="test_project",
        )

    assert ERROR_MESSAGES["INVALID_OBJECT"].format("json", "") in str(exc.value)


def test_generate_token_missing_access_token(mocker, requests_mock):
    """
    Given:
    - An auth endpoint that returns 200 with valid JSON but no access_token field.

    When:
    - Constructing the Client.

    Then:
    - A DemistoException is raised with the TOKEN_GENERATION_FAILED message.
    """
    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    requests_mock.post(
        f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}",
        json={"token_type": "Bearer", "expires_in": 3600},
        status_code=200,
    )

    with pytest.raises(DemistoException) as exc:
        Client(
            server_url=BASE_URL,
            verify_certificate=False,
            proxy=False,
            api_key="test_api_key",
            project_id="test_project",
        )

    assert ERROR_MESSAGES["TOKEN_GENERATION_FAILED"] in str(exc.value)


def test_http_request_persistent_401_json_body(mocker, requests_mock):
    """
    Given:
    - A client with a stale token whose retried request (after token refresh)
      also returns 401 with a JSON body.

    When:
    - get_alert_list is called.

    Then:
    - A DemistoException is raised with the "Unauthorized request" message.
    """
    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "stale_token"},
    )
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=auth_response, status_code=200)

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json={"error": "unauthorized"}, status_code=401)

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )

    with pytest.raises(DemistoException) as exc:
        client.get_alert_list(query_params={"pageSize": 1})

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_http_request_persistent_401_non_json_body(mocker, requests_mock):
    """
    Given:
    - A client with a stale token whose retried request (after token refresh)
      returns 401 with a plain-text (non-JSON) body.

    When:
    - get_alert_list is called.

    Then:
    - A DemistoException is raised with the "Unauthorized request" message
      (the ValueError fallback path inside the elif-401 branch is taken).
    """
    mocker.patch(
        "GoogleThreatIntelligenceRSAlerts.get_integration_context",
        return_value={"access_token": "stale_token"},
    )
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    auth_response = util_load_json("test_data/auth_token.json")
    requests_mock.post(f"{AUTH_BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=auth_response, status_code=200)

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, text="Unauthorized", status_code=401)

    client = Client(
        server_url=BASE_URL,
        verify_certificate=False,
        proxy=False,
        api_key="test_api_key",
        project_id="test_project",
    )

    with pytest.raises(DemistoException) as exc:
        client.get_alert_list(query_params={"pageSize": 1})

    assert ERROR_MESSAGES["UNAUTHORIZED_REQUEST"].format(401, "").rstrip(" .") in str(exc.value)


def test_http_request_response_type_response(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful API response.

    When:
    - http_request is called with response_type="response".

    Then:
    - The raw response object is returned (not parsed JSON).
    """
    alert_list = util_load_json("test_data/alert_list.json")
    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json=alert_list, status_code=200)

    result = mock_client.http_request(
        method="GET",
        url_suffix=ENDPOINTS["ALERT_LIST"].format("test_project"),
        response_type="response",
    )

    assert result.status_code == 200
    assert result.json() == alert_list


def test_http_request_response_type_other(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful API response.

    When:
    - http_request is called with an unrecognised response_type string.

    Then:
    - The raw response object is returned via the else branch.
    """
    alert_list = util_load_json("test_data/alert_list.json")
    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json=alert_list, status_code=200)

    result = mock_client.http_request(
        method="GET",
        url_suffix=ENDPOINTS["ALERT_LIST"].format("test_project"),
        response_type="raw",
    )

    assert result.status_code == 200


def test_http_request_json_parse_error(mock_client, requests_mock):
    """
    Given:
    - A valid client and a 200 response that contains non-JSON body.

    When:
    - http_request is called with response_type="json".

    Then:
    - A DemistoException is raised because the response cannot be parsed as JSON.
    """
    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, text="not-valid-json", status_code=200)

    with pytest.raises(DemistoException) as exc:
        mock_client.http_request(
            method="GET",
            url_suffix=ENDPOINTS["ALERT_LIST"].format("test_project"),
            response_type="json",
        )

    assert ERROR_MESSAGES["INVALID_OBJECT"].format("json", "") in str(exc.value)


@pytest.mark.parametrize(
    "input_list,expected",
    [
        (["keep", "", None, [], {}], ["keep"]),
        (["", None, [], {}], []),
        ([1, None, 2, ""], [1, 2]),
    ],
)
def test_remove_empty_elements_for_fetch_filters_empty_values_from_list(input_list, expected):
    """
    Given:
    - A list containing a mix of non-empty and empty values (None, "", [], {}).

    When:
    - remove_empty_elements_for_fetch is called.

    Then:
    - Empty values are removed; non-empty values are preserved in order.
    """
    from GoogleThreatIntelligenceRSAlerts import remove_empty_elements_for_fetch

    assert remove_empty_elements_for_fetch(input_list) == expected


def test_remove_empty_elements_for_fetch_recursively_cleans_nested_list():
    """
    Given:
    - A list containing a nested list that itself has empty elements.

    When:
    - remove_empty_elements_for_fetch is called.

    Then:
    - Empty elements are removed from the nested list too.
    """
    from GoogleThreatIntelligenceRSAlerts import remove_empty_elements_for_fetch

    assert remove_empty_elements_for_fetch([["a", ""], "b"]) == [["a"], "b"]


def test_remove_empty_elements_for_fetch_list_containing_dict_cleans_both():
    """
    Given:
    - A list containing a dict that has some empty-valued keys.

    When:
    - remove_empty_elements_for_fetch is called.

    Then:
    - Empty keys are removed from the nested dict and the dict itself is kept.
    """
    from GoogleThreatIntelligenceRSAlerts import remove_empty_elements_for_fetch

    result = remove_empty_elements_for_fetch([{"key": "val", "empty": None}])

    assert result == [{"key": "val"}]


def test_test_module_with_is_fetch_calls_fetch_incidents_in_test_mode(mock_client, mocker):
    """
    Given:
    - Integration params with isFetch=True.

    When:
    - test_module is invoked.

    Then:
    - fetch_incidents is called with is_test=True instead of get_alert_list.
    - "ok" is returned.
    """
    from GoogleThreatIntelligenceRSAlerts import test_module

    params = {"isFetch": True, "first_fetch": "3 days", "max_fetch": "10"}
    mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto.params", return_value=params)
    mock_fetch = mocker.patch("GoogleThreatIntelligenceRSAlerts.fetch_incidents", return_value=([], {}))

    result = test_module(client=mock_client)

    assert result == "ok"
    mock_fetch.assert_called_once_with(mock_client, {}, params, is_test=True)


def test_test_module_with_is_fetch_invalid_params_raises(mock_client, mocker):
    """
    Given:
    - Integration params with isFetch=True and a max_fetch value exceeding MAX_FETCH.

    When:
    - test_module is invoked.

    Then:
    - ValueError propagates from the fetch_incidents parameter validation.
    """
    from GoogleThreatIntelligenceRSAlerts import test_module

    params = {"isFetch": True, "first_fetch": "3 days", "max_fetch": str(MAX_FETCH + 1)}
    mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto.params", return_value=params)
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    with pytest.raises(ValueError) as exc:
        test_module(client=mock_client)

    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(MAX_FETCH + 1, MAX_FETCH) in str(exc.value)


def _make_alert(
    alert_id: str,
    update_time: str = "2026-04-22T06:43:07Z",
    create_time: str | None = "2026-04-22T06:43:07Z",
    display_name: str = "Test Alert",
    severity: str = "SEVERITY_LEVEL_HIGH",
) -> dict:
    """Build a minimal alert dict for use in fetch_incidents tests."""
    alert: dict = {
        "name": f"projects/test-project/alerts/{alert_id}",
        "state": "NEW",
        "audit": {"updateTime": update_time},
        "displayName": display_name,
        "severityAnalysis": {"severityLevel": severity},
    }
    if create_time is not None:
        alert["audit"]["createTime"] = create_time
    return alert


def test_validate_rs_fetch_params_all_valid():
    """
    Given:
    - All fetch params are within valid ranges and contain only accepted values.

    When:
    - validate_rs_fetch_params is called.

    Then:
    - No exception is raised.
    """
    from GoogleThreatIntelligenceRSAlerts import validate_rs_params

    validate_rs_params(
        is_command=False,
        max_fetch_raw=100,
        relevance_level=["low", "medium"],
        severity_level=["high"],
        priority_level=["critical"],
        status=["new", "read"],
        threat_scenarios=["data leak"],
    )


@pytest.mark.parametrize("bad_value", [0, -5, MAX_FETCH + 1])
def test_validate_rs_fetch_params_invalid_max_fetch(bad_value):
    """
    Given:
    - max_fetch_raw is outside the valid range [1, MAX_FETCH].

    When:
    - validate_rs_fetch_params is called.

    Then:
    - ValueError is raised containing the INVALID_MAX_FETCH message.
    """
    from GoogleThreatIntelligenceRSAlerts import validate_rs_params

    with pytest.raises(ValueError) as exc:
        validate_rs_params(is_command=False, max_fetch_raw=bad_value)

    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(bad_value, MAX_FETCH) in str(exc.value)


@pytest.mark.parametrize(
    "field,kwargs",
    [
        ("relevance_level", {"relevance_level": ["extreme"]}),
        ("severity_level", {"severity_level": ["critical"]}),
        ("priority_level", {"priority_level": ["urgent"]}),
        ("status", {"status": ["pending"]}),
        ("threat_scenarios", {"threat_scenarios": ["ransomware"]}),
    ],
)
def test_validate_rs_fetch_params_invalid_single_field(field, kwargs):
    """
    Given:
    - One filter field contains an invalid value.

    When:
    - validate_rs_fetch_params is called.

    Then:
    - ValueError is raised mentioning both the bad value and the field name.
    """
    from GoogleThreatIntelligenceRSAlerts import validate_rs_params

    with pytest.raises(ValueError) as exc:
        validate_rs_params(is_command=False, **kwargs)

    error_text = str(exc.value)
    bad_value = list(kwargs.values())[0][0]
    assert bad_value in error_text
    assert field in error_text


def test_validate_rs_fetch_params_collects_multiple_errors():
    """
    Given:
    - Multiple invalid params: bad max_fetch, invalid relevance_level, invalid status.

    When:
    - validate_rs_fetch_params is called.

    Then:
    - A single ValueError is raised whose message contains all three error descriptions.
    """
    from GoogleThreatIntelligenceRSAlerts import validate_rs_params

    with pytest.raises(ValueError) as exc:
        validate_rs_params(
            is_command=False,
            max_fetch_raw=0,
            relevance_level=["extreme"],
            status=["pending"],
        )

    error_text = str(exc.value)
    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(0, MAX_FETCH) in error_text
    assert "extreme" in error_text
    assert "pending" in error_text


def test_get_filter_params_signature_all_empty():
    """
    Given:
    - All filter lists are empty.

    When:
    - _get_filter_params_signature is called.

    Then:
    - Returns the empty-segment signature "||||".
    """
    from GoogleThreatIntelligenceRSAlerts import _get_filter_params_signature

    assert _get_filter_params_signature([], [], [], [], []) == "||||"


def test_get_filter_params_signature_is_order_independent():
    """
    Given:
    - The same filter values provided in different orderings.

    When:
    - _get_filter_params_signature is called twice.

    Then:
    - Both calls return the same signature.
    """
    from GoogleThreatIntelligenceRSAlerts import _get_filter_params_signature

    sig1 = _get_filter_params_signature(["high", "low"], ["medium"], [], ["new"], [])
    sig2 = _get_filter_params_signature(["low", "high"], ["medium"], [], ["new"], [])

    assert sig1 == sig2


def test_get_filter_params_signature_is_case_insensitive():
    """
    Given:
    - Filter values in mixed case vs lower case.

    When:
    - _get_filter_params_signature is called for each variant.

    Then:
    - Both calls produce the same signature.
    """
    from GoogleThreatIntelligenceRSAlerts import _get_filter_params_signature

    assert _get_filter_params_signature(["High"], ["Low"], [], ["New"], []) == _get_filter_params_signature(
        ["high"], ["low"], [], ["new"], []
    )


def test_get_filter_params_signature_differs_when_params_differ():
    """
    Given:
    - Two distinct sets of filter params.

    When:
    - _get_filter_params_signature is called for each set.

    Then:
    - The returned signatures are different.
    """
    from GoogleThreatIntelligenceRSAlerts import _get_filter_params_signature

    assert _get_filter_params_signature(["high"], [], [], [], []) != _get_filter_params_signature(["low"], [], [], [], [])


def test_get_filter_params_signature_excludes_invalid_values():
    """
    Given:
    - A filter list that contains only invalid values.

    When:
    - _get_filter_params_signature is called.

    Then:
    - Invalid values are dropped and the segment is empty, matching the all-empty signature.
    """
    from GoogleThreatIntelligenceRSAlerts import _get_filter_params_signature

    assert _get_filter_params_signature(["invalid_level"], [], [], [], []) == "||||"


def test_build_rs_filter_string_time_only():
    """
    Given:
    - Only a last_update_time, no optional filter dimensions.

    When:
    - _build_rs_filter_string is called.

    Then:
    - The filter string contains only the update_time lower-bound condition.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(is_command=False, last_update_time="2026-04-22T00:00:00Z")

    assert result == 'audit.update_time >= "2026-04-22T00:00:00Z"'


def test_build_rs_filter_string_single_value_no_parens():
    """
    Given:
    - A single severity_level value.

    When:
    - _build_rs_filter_string is called.

    Then:
    - The condition is added with AND but without enclosing parentheses (single value).
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(is_command=False, last_update_time="2026-04-22T00:00:00Z", severity_level=["high"])

    assert 'severity_analysis.severity_level = "SEVERITY_LEVEL_HIGH"' in result
    assert " AND " in result
    assert "(" not in result


def test_build_rs_filter_string_multiple_values_uses_or_with_parens():
    """
    Given:
    - Two severity_level values.

    When:
    - _build_rs_filter_string is called.

    Then:
    - The two conditions are combined with OR and wrapped in parentheses.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(is_command=False, last_update_time="2026-04-22T00:00:00Z", severity_level=["high", "low"])

    assert "SEVERITY_LEVEL_HIGH" in result
    assert "SEVERITY_LEVEL_LOW" in result
    assert " OR " in result
    assert "(" in result


def test_build_rs_filter_string_all_dimensions_joined_with_and():
    """
    Given:
    - One value for each of the five optional filter dimensions.

    When:
    - _build_rs_filter_string is called.

    Then:
    - All five dimension conditions are present in the filter string joined by AND.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(
        is_command=False,
        last_update_time="2026-04-22T00:00:00Z",
        relevance_level=["high"],
        severity_level=["high"],
        priority_level=["critical"],
        status=["new"],
        threat_scenarios=["data leak"],
    )

    assert "relevance_analysis.relevance_level" in result
    assert "severity_analysis.severity_level" in result
    assert "priority_analysis.priority_level" in result
    assert 'state = "NEW"' in result
    assert 'detail.detail_type = "data_leak"' in result
    assert result.count(" AND ") == 5


def test_build_rs_filter_string_ignores_invalid_values():
    """
    Given:
    - A severity_level list that mixes one valid and one invalid value.

    When:
    - _build_rs_filter_string is called.

    Then:
    - Only the valid API value appears; the invalid string is silently dropped.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(
        is_command=False, last_update_time="2026-04-22T00:00:00Z", severity_level=["high", "extreme"]
    )

    assert "SEVERITY_LEVEL_HIGH" in result
    assert "extreme" not in result


def test_fetch_incidents_first_run_creates_incident(mock_client, mocker):
    """
    Given:
    - Empty last_run (first fetch run).
    - API returns the full alert from test_data/alert_list.json.

    When:
    - fetch_incidents is called.

    Then:
    - One incident is returned with the correct name, occurred, severity, and full rawJSON/details.
    - next_run contains last_update_time, alert_ids, and filter_params_signature keys.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alert_data = util_load_json("test_data/alert_list.json")
    mocker.patch.object(mock_client, "get_alert_list", return_value=alert_data)

    expected_raw = util_load_json("test_data/incident_data.json")

    incidents, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["name"] == "Test Alert 1"
    assert incident["occurred"] == "2026-04-22T06:43:07.513Z"
    assert incident["severity"] == RS_SEVERITY_TO_XSOAR_SEVERITY["SEVERITY_LEVEL_HIGH"]

    # rawJSON now includes mirror params (mirror_id, mirror_direction, mirror_instance); strip them before comparing.
    MIRROR_KEYS = {"mirror_id", "mirror_direction", "mirror_instance"}
    raw_without_mirror = {k: v for k, v in json.loads(incident["rawJSON"]).items() if k not in MIRROR_KEYS}
    assert raw_without_mirror == expected_raw
    details_without_mirror = {k: v for k, v in json.loads(incident["details"]).items() if k not in MIRROR_KEYS}
    assert details_without_mirror == expected_raw

    assert "alert-1" in next_run["alert_ids"]
    assert "last_update_time" in next_run
    assert "filter_params_signature" in next_run


def test_fetch_incidents_subsequent_run_uses_stored_last_update_time(mock_client, mocker):
    """
    Given:
    - last_run contains a previous checkpoint with matching filter signature and a stored
      last_update_time of "2026-04-22T00:00:00Z".
    - API returns one new alert.

    When:
    - fetch_incidents is called.

    Then:
    - The filter passed to the API uses the stored last_update_time, not first_fetch.
    - next_run.last_update_time equals the alert's updateTime.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alert = _make_alert("alert-2", update_time="2026-04-23T10:00:00Z")
    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": [alert]})

    last_run = {
        "last_update_time": "2026-04-22T00:00:00Z",
        "alert_ids": [],
        "filter_params_signature": "||||",
    }

    incidents, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 1
    assert next_run["last_update_time"] == "2026-04-23T10:00:00Z"
    call_params = mock_get.call_args[0][0]
    assert "2026-04-22T00:00:00Z" in call_params["filter"]


@pytest.mark.parametrize(
    "api_alerts, existing_ids, expected_count, expected_ids",
    [
        pytest.param(
            [_make_alert("alert-1")],
            ["alert-1"],
            0,
            {"alert-1"},
            id="all_duplicates_skipped",
        ),
        pytest.param(
            [
                _make_alert("alert-1", update_time="2026-04-22T06:00:00Z"),
                _make_alert("alert-2", update_time="2026-04-23T06:00:00Z"),
            ],
            ["alert-1"],
            1,
            {"alert-1", "alert-2"},
            id="partial_deduplication",
        ),
    ],
)
def test_fetch_incidents_deduplication(mock_client, mocker, api_alerts, existing_ids, expected_count, expected_ids):
    """
    Given:
    - A last_run with some existing alert_ids and an API response containing duplicate and/or new alerts.

    When:
    - fetch_incidents is called.

    Then:
    - Only new (non-duplicate) alerts become incidents.
    - next_run.alert_ids contains all seen IDs from both the previous and current run.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": api_alerts})

    last_run = {"last_update_time": "2026-04-21T00:00:00Z", "alert_ids": existing_ids, "filter_params_signature": "||||"}

    incidents, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == expected_count
    assert set(next_run["alert_ids"]) == expected_ids


def test_fetch_incidents_filter_params_changed_resets_to_first_fetch(mock_client, mocker):
    """
    Given:
    - last_run has a stored filter_params_signature that differs from the params in use.
    - last_run also has an old last_update_time.

    When:
    - fetch_incidents is called with no filter params (signature "||||").

    Then:
    - The old last_update_time is NOT used in the API filter; first_fetch time is used instead.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    last_run = {
        "last_update_time": "2026-01-01T00:00:00Z",
        "alert_ids": [],
        "filter_params_signature": "|high||new|",
    }
    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    call_params = mock_get.call_args[0][0]
    assert "2026-01-01T00:00:00Z" not in call_params["filter"]


def test_fetch_incidents_filter_params_unchanged_uses_stored_time(mock_client, mocker):
    """
    Given:
    - last_run has a stored filter_params_signature that matches the current params.
    - last_run has a specific last_update_time.

    When:
    - fetch_incidents is called.

    Then:
    - The stored last_update_time is used in the API filter.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents, _get_filter_params_signature

    stored_time = "2026-04-20T00:00:00Z"
    matching_sig = _get_filter_params_signature([], ["high"], [], [], [])

    last_run = {"last_update_time": stored_time, "alert_ids": [], "filter_params_signature": matching_sig}
    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10", "severity_level": ["high"]})

    call_params = mock_get.call_args[0][0]
    assert stored_time in call_params["filter"]


def test_fetch_incidents_is_test_returns_empty_after_api_call(mock_client, mocker):
    """
    Given:
    - is_test=True with valid params.
    - API returns one alert.

    When:
    - fetch_incidents is called.

    Then:
    - Returns ([], {}) without creating incidents.
    - The API was still called once (to verify connectivity).
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": [_make_alert("alert-1")]})

    incidents, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"}, is_test=True)

    assert incidents == []
    assert next_run == {}
    mock_get.assert_called_once()


@pytest.mark.parametrize(
    "params, error_fragments",
    [
        pytest.param(
            {"first_fetch": "3 days", "max_fetch": str(MAX_FETCH + 1)},
            [ERROR_MESSAGES["INVALID_MAX_FETCH"].format(MAX_FETCH + 1, MAX_FETCH)],
            id="invalid_max_fetch",
        ),
        pytest.param(
            {"first_fetch": "3 days", "max_fetch": "10", "severity_level": ["critical"]},
            ["severity_level", "critical"],
            id="invalid_severity",
        ),
    ],
)
def test_fetch_incidents_is_test_invalid_params_raises_before_api_call(mock_client, mocker, params, error_fragments):
    """
    Given:
    - is_test=True with invalid fetch params (max_fetch exceeding the limit or an invalid severity).

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised containing each expected fragment.
    - The API is never called.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, params, is_test=True)

    for fragment in error_fragments:
        assert fragment in str(exc.value)
    mock_get.assert_not_called()


def test_fetch_incidents_empty_api_response_preserves_last_update_time(mock_client, mocker):
    """
    Given:
    - last_run has a stored last_update_time.
    - API returns an empty alerts list.

    When:
    - fetch_incidents is called.

    Then:
    - No incidents are created.
    - next_run.last_update_time equals the stored value (unchanged).
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    stored_time = "2026-04-22T00:00:00Z"
    last_run = {"last_update_time": stored_time, "alert_ids": [], "filter_params_signature": "||||"}
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    incidents, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents == []
    assert next_run["last_update_time"] == stored_time


@pytest.mark.parametrize(
    "severity,expected_xsoar_severity",
    [
        ("SEVERITY_LEVEL_LOW", 1),
        ("SEVERITY_LEVEL_MEDIUM", 2),
        ("SEVERITY_LEVEL_HIGH", 3),
        ("SEVERITY_LEVEL_UNSPECIFIED", 0),
        ("UNKNOWN_SEVERITY_XYZ", 0),
    ],
)
def test_fetch_incidents_severity_mapped_to_xsoar(mock_client, mocker, severity, expected_xsoar_severity):
    """
    Given:
    - An alert with a specific RS severity level.

    When:
    - fetch_incidents is called.

    Then:
    - The incident severity matches the expected XSOAR severity integer.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": [_make_alert("alert-1", severity=severity)]})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents[0]["severity"] == expected_xsoar_severity


@pytest.mark.parametrize(
    "alert, incident_field, expected_value",
    [
        pytest.param(
            _make_alert("alert-99", display_name=""),
            "name",
            "alert-99",
            id="empty_display_name_uses_alert_id",
        ),
        pytest.param(
            _make_alert("alert-1", update_time="2026-04-22T08:00:00Z", create_time=None),
            "occurred",
            "2026-04-22T08:00:00Z",
            id="no_create_time_falls_back_to_update_time",
        ),
    ],
)
def test_fetch_incidents_alert_field_fallback(mock_client, mocker, alert, incident_field, expected_value):
    """
    Given:
    - An alert with a missing or empty field (displayName or createTime).

    When:
    - fetch_incidents is called.

    Then:
    - The incident uses the fallback value for the affected field.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": [alert]})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert incidents[0][incident_field] == expected_value


def test_fetch_incidents_max_fetch_capped_at_max_fetch(mock_client, mocker):
    """
    Given:
    - max_fetch param exceeds MAX_FETCH (200).

    When:
    - fetch_incidents is called.

    Then:
    - The pageSize passed to the API is capped at MAX_FETCH.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "500"})

    assert mock_get.call_args[0][0]["pageSize"] == MAX_FETCH


def test_fetch_incidents_negative_max_fetch_raises(mock_client, mocker):
    """
    Given:
    - max_fetch param is a negative value (-1).

    When:
    - fetch_incidents is called.

    Then:
    - ValueError is raised with the INVALID_MAX_FETCH message.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    with pytest.raises(ValueError) as exc:
        fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "-1"})

    assert ERROR_MESSAGES["INVALID_MAX_FETCH"].format(-1, MAX_FETCH) in str(exc.value)


def test_fetch_incidents_next_run_uses_last_alert_update_time(mock_client, mocker):
    """
    Given:
    - API returns two alerts ordered by updateTime, with the second having the later time.

    When:
    - fetch_incidents is called.

    Then:
    - next_run.last_update_time equals the last alert's updateTime.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alerts = [
        _make_alert("alert-1", update_time="2026-04-22T06:00:00Z"),
        _make_alert("alert-2", update_time="2026-04-23T12:00:00Z"),
    ]
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": alerts})

    _, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert next_run["last_update_time"] == "2026-04-23T12:00:00Z"


def test_fetch_incidents_alert_with_empty_name_is_skipped(mock_client, mocker):
    """
    Given:
    - API returns an alert with an empty "name" field (no alert_id can be extracted).

    When:
    - fetch_incidents is called.

    Then:
    - The alert is skipped and no incident is created.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alert = _make_alert("alert-1")
    alert["name"] = ""
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": [alert]})

    incidents, _ = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert len(incidents) == 0


def test_fetch_incidents_alert_ids_accumulated_across_runs(mock_client, mocker):
    """
    Given:
    - last_run already has "alert-1" in alert_ids.
    - API returns two new alerts: alert-2 and alert-3.

    When:
    - fetch_incidents is called.

    Then:
    - next_run.alert_ids contains all three IDs from both the previous and current run.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alerts = [
        _make_alert("alert-2", update_time="2026-04-22T07:00:00Z"),
        _make_alert("alert-3", update_time="2026-04-23T00:00:00Z"),
    ]
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": alerts})

    last_run = {"last_update_time": "2026-04-22T00:00:00Z", "alert_ids": ["alert-1"], "filter_params_signature": "||||"}

    _, next_run = fetch_incidents(mock_client, last_run, {"first_fetch": "3 days", "max_fetch": "10"})

    assert set(next_run["alert_ids"]) == {"alert-1", "alert-2", "alert-3"}


def test_fetch_incidents_query_uses_order_by_update_time_asc(mock_client, mocker):
    """
    Given:
    - A valid client and default params.

    When:
    - fetch_incidents is called.

    Then:
    - The orderBy query param sent to the API is "audit.update_time asc".
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10"})

    assert mock_get.call_args[0][0]["orderBy"] == "audit.update_time asc"


def test_fetch_incidents_filter_string_includes_active_filters(mock_client, mocker):
    """
    Given:
    - params includes severity_level=["high"] and status=["new"].

    When:
    - fetch_incidents is called.

    Then:
    - The filter param passed to the API contains both the severity and status conditions.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    fetch_incidents(
        mock_client,
        {},
        {"first_fetch": "3 days", "max_fetch": "10", "severity_level": ["high"], "status": ["new"]},
    )

    filter_str = mock_get.call_args[0][0]["filter"]
    assert "SEVERITY_LEVEL_HIGH" in filter_str
    assert 'state = "NEW"' in filter_str


def test_fetch_incidents_next_run_stores_current_filter_signature(mock_client, mocker):
    """
    Given:
    - params includes severity_level=["high"].

    When:
    - fetch_incidents is called.

    Then:
    - next_run.filter_params_signature reflects the active filter params so the next
      run can detect changes.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents, _get_filter_params_signature

    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": []})

    _, next_run = fetch_incidents(mock_client, {}, {"first_fetch": "3 days", "max_fetch": "10", "severity_level": ["high"]})

    expected_sig = _get_filter_params_signature([], ["high"], [], [], [])
    assert next_run["filter_params_signature"] == expected_sig


def test_gti_rs_alert_list_success(mock_client, requests_mock):
    """
    Given:
    - A valid client and valid alert list response from test_data/alert_list.json.

    When:
    - gti_rs_alert_list_command is called with default arguments.

    Then:
    - CommandResults outputs_prefix is correct.
    - The full context output matches test_data/alert_list_context.json.
    - The full human-readable output matches test_data/alert_list_hr.md.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_list_command

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json=util_load_json("test_data/alert_list.json"), status_code=200)

    result = gti_rs_alert_list_command(mock_client, {})

    expected_context = util_load_json("test_data/alert_list_context.json")
    with open("test_data/alert_list_hr.md", encoding="utf-8") as f:
        expected_hr = f.read()

    assert result.outputs_prefix == "GoogleThreatIntelligenceRSAlerts.Alert"
    assert result.outputs == expected_context  # type: ignore
    assert result.readable_output == expected_hr  # type: ignore


def test_gti_rs_alert_list_no_alerts(mock_client, requests_mock):
    """
    Given:
    - A valid client and an empty alert list response.

    When:
    - gti_rs_alert_list_command is called.

    Then:
    - CommandResults is returned with a message indicating no alerts were found.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_list_command

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json={"alerts": []}, status_code=200)

    result = gti_rs_alert_list_command(mock_client, {})

    assert "No RS Alerts were found" in result.readable_output  # type: ignore


@pytest.mark.parametrize(
    "args, expected_key, expected_value",
    [
        pytest.param(
            {"page_size": "20"},
            "pageSize",
            20,
            id="page_size_maps_to_pageSize",
        ),
        pytest.param(
            {"order_by": "Asc"},
            "orderBy",
            "asc",
            id="order_by_asc_in_orderBy",
        ),
        pytest.param(
            {"sort_by": "Create Time", "create_time": "2026-04-22T06:43:07Z"},
            "orderBy",
            "audit.create_time",
            id="sort_by_create_time_in_orderBy",
        ),
    ],
)
def test_gti_rs_alert_list_query_params(mock_client, mocker, args, expected_key, expected_value):
    """
    Given:
    - Various combinations of alert list arguments (page_size, order_by, sort_by/create_time).

    When:
    - gti_rs_alert_list_command is called.

    Then:
    - The expected query parameter key contains the expected value.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_list_command

    mock_get = mocker.patch.object(mock_client, "get_alert_list", return_value=util_load_json("test_data/alert_list.json"))

    gti_rs_alert_list_command(mock_client, args)

    query_params = mock_get.call_args[0][0]
    actual = query_params[expected_key]
    if isinstance(expected_value, str):
        assert expected_value in actual
    else:
        assert actual == expected_value

    if args.get("sort_by") == "Create Time":
        assert 'audit.create_time >= "2026-04-22T06:43:07Z"' in query_params["filter"]


@pytest.mark.parametrize(
    "args, expected_fragment",
    [
        pytest.param({"page_size": "2147483648"}, "invalid value for 'page_size'", id="invalid_page_size"),
        pytest.param({"order_by": "Invalid"}, "invalid value for 'order_by'", id="invalid_order_by"),
        pytest.param({"severity_level": "Invalid"}, "invalid value for 'severity_level'", id="invalid_severity_level"),
    ],
)
def test_gti_rs_alert_list_invalid_args(mock_client, args, expected_fragment):
    """
    Given:
    - An invalid value for one of page_size, order_by, or severity_level.

    When:
    - gti_rs_alert_list_command is called.

    Then:
    - ValueError is raised whose message contains the expected field name.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_list_command

    with pytest.raises(ValueError) as exc:
        gti_rs_alert_list_command(mock_client, args)

    assert expected_fragment in str(exc.value).lower()


@pytest.mark.parametrize(
    "kwargs, expected_fragment",
    [
        pytest.param({"page_size": 0}, "invalid value for 'page_size'", id="invalid_page_size"),
        pytest.param({"order_by": "Invalid"}, "invalid value for 'order_by'", id="invalid_order_by"),
        pytest.param({"sort_by": "Invalid"}, "invalid value for 'sort_by'", id="invalid_sort_by"),
    ],
)
def test_validate_rs_params_command_mode_invalid_param(kwargs, expected_fragment):
    """
    Given:
    - An invalid value for one of page_size, order_by, or sort_by in command mode.

    When:
    - validate_rs_params is called with is_command=True.

    Then:
    - ValueError is raised whose message contains the expected field name.
    """
    from GoogleThreatIntelligenceRSAlerts import validate_rs_params

    with pytest.raises(ValueError) as exc:
        validate_rs_params(is_command=True, **kwargs)

    assert expected_fragment in str(exc.value).lower()


@pytest.mark.parametrize(
    "kwargs, present, absent, min_and_count",
    [
        pytest.param(
            {"is_command": True, "create_time": "2026-04-20T00:00:00Z", "update_time": "2026-04-21T00:00:00Z"},
            ['audit.create_time >= "2026-04-20T00:00:00Z"', 'audit.update_time >= "2026-04-21T00:00:00Z"', " AND "],
            [],
            0,
            id="both_create_and_update_time",
        ),
        pytest.param(
            {"is_command": True, "update_time": "2026-04-21T00:00:00Z"},
            ['audit.update_time >= "2026-04-21T00:00:00Z"'],
            ["create_time"],
            0,
            id="only_update_time",
        ),
        pytest.param(
            {"is_command": True, "create_time": "2026-04-20T00:00:00Z"},
            ['audit.create_time >= "2026-04-20T00:00:00Z"'],
            ["update_time"],
            0,
            id="only_create_time",
        ),
        pytest.param(
            {"is_command": True, "severity_level": ["high"]},
            ["SEVERITY_LEVEL_HIGH"],
            ["audit.create_time", "audit.update_time"],
            0,
            id="no_time_filters_severity_only",
        ),
        pytest.param(
            {
                "is_command": True,
                "create_time": "2026-04-20T00:00:00Z",
                "update_time": "2026-04-21T00:00:00Z",
                "relevance_level": ["high"],
                "severity_level": ["medium"],
                "priority_level": ["critical"],
                "status": ["new"],
                "threat_scenarios": ["data leak"],
            },
            [
                'audit.create_time >= "2026-04-20T00:00:00Z"',
                'audit.update_time >= "2026-04-21T00:00:00Z"',
                "RELEVANCE_LEVEL_HIGH",
                "SEVERITY_LEVEL_MEDIUM",
                "PRIORITY_LEVEL_CRITICAL",
                'state = "NEW"',
                'detail.detail_type = "data_leak"',
            ],
            [],
            5,
            id="all_filters",
        ),
        pytest.param(
            {"is_command": False, "last_update_time": "2026-04-20T00:00:00Z", "severity_level": ["high"]},
            ['audit.update_time >= "2026-04-20T00:00:00Z"', "SEVERITY_LEVEL_HIGH"],
            [],
            0,
            id="fetch_mode_update_time_and_severity",
        ),
        pytest.param(
            {"is_command": True, "update_time": "2026-04-20T00:00:00Z", "severity_level": ["high"]},
            ['audit.update_time >= "2026-04-20T00:00:00Z"', "SEVERITY_LEVEL_HIGH"],
            [],
            0,
            id="command_mode_update_time_and_severity",
        ),
    ],
)
def test_build_rs_filter_string(kwargs, present, absent, min_and_count):
    """
    Given:
    - Various combinations of filter arguments in command or fetch mode.

    When:
    - _build_rs_filter_string is called.

    Then:
    - The result contains all expected substrings and none of the unexpected ones.
    - If min_and_count > 0, the result has at least that many ' AND ' separators.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_filter_string

    result = _build_rs_filter_string(**kwargs)

    for fragment in present:
        assert fragment in result
    for fragment in absent:
        assert fragment not in result
    if min_and_count:
        assert result.count(" AND ") >= min_and_count


def test_client_get_alert_calls_correct_endpoint(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful API response for a single alert.

    When:
    - get_alert is called with a specific alert_id.

    Then:
    - The correct GET endpoint is called and the response is returned.
    """
    alert_get = util_load_json("test_data/alert_get.json")
    alert_url = f"{BASE_URL}{ENDPOINTS['ALERT_GET'].format('test_project', 'alert-get-1')}"
    requests_mock.get(alert_url, json=alert_get, status_code=200)

    result = mock_client.get_alert("alert-get-1")

    assert result == alert_get
    assert requests_mock.last_request.path == "/v1beta/projects/test_project/alerts/alert-get-1"


def test_build_rs_alert_get_output_returns_correct_hr_fields():
    """
    Given:
    - A full alert dict with all analysis fields populated.

    When:
    - _build_rs_alert_get_output is called.

    Then:
    - The readable_output matches the expected markdown including all field labels and values.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_alert_get_output

    alert = util_load_json("test_data/alert_get.json")

    context, readable_output = _build_rs_alert_get_output(alert, "GTI RS Alert Information")

    with open("test_data/alert_get_hr.md", encoding="utf-8") as f:
        expected_readable_output = f.read()
    assert readable_output == expected_readable_output


def test_build_rs_alert_get_output_formats_levels_correctly():
    """
    Given:
    - An alert with API-format priority/severity/relevance/confidence values.

    When:
    - _build_rs_alert_get_output is called.

    Then:
    - The HR shows human-readable capitalized values for all level and confidence fields
      (e.g. "Low" not "PRIORITY_LEVEL_LOW", "High" not "CONFIDENCE_LEVEL_HIGH").
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_alert_get_output

    alert = util_load_json("test_data/alert_get.json")

    _, readable_output = _build_rs_alert_get_output(alert, "GTI RS Alert Information")

    with open("test_data/alert_get_hr.md", encoding="utf-8") as f:
        expected_readable_output = f.read()
    assert readable_output == expected_readable_output


def test_gti_rs_alert_get_success(mock_client, requests_mock):
    """
    Given:
    - A valid client and a valid alert_id argument.

    When:
    - gti_rs_alert_get_command is called.

    Then:
    - CommandResults has the correct outputs_prefix, outputs_key_field, raw_response,
      and readable_output matching the full expected markdown table.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_get_command

    alert_get = util_load_json("test_data/alert_get.json")
    alert_url = f"{BASE_URL}{ENDPOINTS['ALERT_GET'].format('test_project', 'alert-get-1')}"
    requests_mock.get(alert_url, json=alert_get, status_code=200)

    result = gti_rs_alert_get_command(mock_client, {"alert_id": "alert-get-1"})

    with open("test_data/alert_get_hr.md", encoding="utf-8") as f:
        expected_readable_output = f.read()
    expected_context = util_load_json("test_data/alert_get_context.json")
    assert result.outputs_prefix == OUTPUT_PREFIX
    assert result.outputs_key_field == "name"
    assert result.raw_response == alert_get
    assert result.outputs == expected_context  # type: ignore
    assert result.readable_output == expected_readable_output  # type: ignore


@pytest.mark.parametrize(
    "args",
    [
        pytest.param({"alert_id": ""}, id="empty_alert_id"),
        pytest.param({}, id="missing_alert_id"),
    ],
)
def test_gti_rs_alert_get_invalid_alert_id_raises(mock_client, args):
    """
    Given:
    - An empty or missing alert_id argument.

    When:
    - gti_rs_alert_get_command is called.

    Then:
    - ValueError is raised with the REQUIRED_ARGUMENT message.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_get_command

    with pytest.raises(ValueError) as exc:
        gti_rs_alert_get_command(mock_client, args)

    assert str(exc.value) == ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")


def test_gti_rs_alert_get_passes_alert_id_to_client(mock_client, mocker):
    """
    Given:
    - A valid alert_id argument.

    When:
    - gti_rs_alert_get_command is called.

    Then:
    - client.get_alert is called with the exact alert_id.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_get_command

    mock_get = mocker.patch.object(mock_client, "get_alert", return_value=util_load_json("test_data/alert_get.json"))

    gti_rs_alert_get_command(mock_client, {"alert_id": "my-alert-123"})

    mock_get.assert_called_once_with("my-alert-123", response_type="json")


def test_client_update_alert_status_calls_correct_endpoint(mock_client, requests_mock):
    """
    Given:
    - A valid client and a successful POST response for alert status update.

    When:
    - update_alert_status is called with a specific alert_id and state.

    Then:
    - The correct POST endpoint is called with the correct request body, and the
      response is returned.
    """
    status_update_response = util_load_json("test_data/alert_status_update.json")
    update_url = f"{BASE_URL}{ENDPOINTS['ALERT_STATUS_UPDATE'].format('test_project', 'alert-status-1', 'read')}"
    requests_mock.post(update_url, json=status_update_response, status_code=200)

    result = mock_client.update_alert_status("alert-status-1", "read")

    assert result == status_update_response


def test_build_rs_alert_status_update_output_returns_correct_hr_and_context():
    """
    Given:
    - A full alert dict with state="READ".

    When:
    - _build_rs_alert_status_update_output is called.

    Then:
    - The readable_output matches the expected markdown.
    - The context matches the expected JSON.
    """
    from GoogleThreatIntelligenceRSAlerts import _build_rs_alert_status_update_output

    alert = util_load_json("test_data/alert_status_update.json")

    context, readable_output = _build_rs_alert_status_update_output(alert, "Alert Status Updated Successfully.")

    with open("test_data/alert_status_update_hr.md", encoding="utf-8") as f:
        expected_readable_output = f.read()
    expected_context = util_load_json("test_data/alert_status_update_context.json")

    assert readable_output == expected_readable_output
    assert context == expected_context


def test_gti_rs_alert_status_update_success(mock_client, requests_mock):
    """
    Given:
    - A valid client, valid alert_id, and valid status argument.

    When:
    - gti_rs_alert_status_update_command is called.

    Then:
    - CommandResults has the correct outputs_prefix, outputs_key_field, raw_response,
      context, and readable_output matching the expected files.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_status_update_command

    status_update_response = util_load_json("test_data/alert_status_update.json")
    update_url = f"{BASE_URL}{ENDPOINTS['ALERT_STATUS_UPDATE'].format('test_project', 'alert-status-1', 'read')}"
    requests_mock.post(update_url, json=status_update_response, status_code=200)

    result = gti_rs_alert_status_update_command(mock_client, {"alert_id": "alert-status-1", "status": "Read"})

    with open("test_data/alert_status_update_hr.md", encoding="utf-8") as f:
        expected_readable_output = f.read()
    expected_context = util_load_json("test_data/alert_status_update_context.json")

    assert result.outputs_prefix == OUTPUT_PREFIX
    assert result.outputs_key_field == "name"
    assert result.raw_response == status_update_response
    assert result.outputs == expected_context
    assert result.readable_output == expected_readable_output


@pytest.mark.parametrize(
    "args, expected_error",
    [
        pytest.param(
            {"alert_id": "", "status": "Read"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("alert_id"), id="empty_alert_id"
        ),
        pytest.param({"status": "Read"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("alert_id"), id="missing_alert_id"),
        pytest.param(
            {"alert_id": "alert-1", "status": ""}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("status"), id="empty_status"
        ),
        pytest.param({"alert_id": "alert-1"}, ERROR_MESSAGES["REQUIRED_ARGUMENT"].format("status"), id="missing_status"),
        pytest.param(
            {"alert_id": "alert-1", "status": "New"},
            "invalid value for 'status'",
            id="new_status_not_allowed",
        ),
        pytest.param(
            {"alert_id": "alert-1", "status": "InvalidStatus"},
            "invalid value for 'status'",
            id="invalid_status",
        ),
    ],
)
def test_gti_rs_alert_status_update_invalid_args_raises(mock_client, args, expected_error):
    """
    Given:
    - Various invalid argument combinations (empty/missing alert_id, empty/missing status,
      disallowed "New" status, or an arbitrary invalid status).

    When:
    - gti_rs_alert_status_update_command is called.

    Then:
    - ValueError is raised with the expected message fragment.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_status_update_command

    with pytest.raises(ValueError) as exc:
        gti_rs_alert_status_update_command(mock_client, args)

    assert expected_error.lower() in str(exc.value).lower()


@pytest.mark.parametrize(
    "input_status, expected_api_state",
    [
        ("Read", "read"),
        ("read", "read"),
        ("False Positive", "falsePositive"),
        ("Tracked Externally", "trackExternally"),
        ("Resolved", "resolve"),
    ],
)
def test_gti_rs_alert_status_update_maps_status_correctly(mock_client, mocker, input_status, expected_api_state):
    """
    Given:
    - A valid alert_id and various status strings (including mixed case and multi-word values).

    When:
    - gti_rs_alert_status_update_command is called.

    Then:
    - client.update_alert_status is called with the correctly mapped API state value.
    """
    from GoogleThreatIntelligenceRSAlerts import gti_rs_alert_status_update_command

    mock_update = mocker.patch.object(
        mock_client,
        "update_alert_status",
        return_value=util_load_json("test_data/alert_status_update.json"),
    )

    gti_rs_alert_status_update_command(mock_client, {"alert_id": "alert-1", "status": input_status})

    mock_update.assert_called_once_with("alert-1", expected_api_state, response_type="json")


def test_mirroring_constants():
    """Verify the correctness of all mirroring-related constants in one place."""
    assert MIRROR_DIRECTION == {"Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
    assert RS_STATE_TO_XSOAR_STATE == {
        "STATE_UNSPECIFIED": "State Unspecified",
        "NEW": "New",
        "READ": "Read",
        "TRIAGED": "Triaged",
        "ESCALATED": "Escalated",
        "FALSE_POSITIVE": "False Positive",
        "RESOLVED": "Resolved",
        "DUPLICATE": "Duplicate",
        "BENIGN": "Benign",
        "NOT_ACTIONABLE": "Not Actionable",
        "TRACKED_EXTERNALLY": "Tracked Externally",
    }
    assert set() == RS_OPEN_STATUSES & RS_CLOSE_STATUSES
    assert set(RS_CLOSE_REASON_MAPPING.keys()) == RS_CLOSE_STATUSES
    assert "New" not in RS_UPDATE_STATUS_HR_LIST
    assert "new" not in RS_UPDATE_STATUS_API_MAP


@pytest.mark.parametrize(
    "mirror_direction_param, expected_direction",
    [
        ("Incoming", "In"),
        ("", None),
    ],
)
def test_get_mirroring_returns_correct_direction(mocker, mirror_direction_param, expected_direction):
    """
    Given:
    - Various mirror_direction integration parameter values.

    When:
    - get_mirroring is called.

    Then:
    - The returned mirror_direction value matches the MIRROR_DIRECTION lookup.
    - mirror_instance is always populated.
    """
    from GoogleThreatIntelligenceRSAlerts import get_mirroring

    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = {"mirror_direction": mirror_direction_param}
    mock_demisto.integrationInstance.return_value = "test-instance"

    result = get_mirroring()

    assert result["mirror_direction"] == expected_direction
    assert result["mirror_instance"] == "test-instance"


@pytest.mark.parametrize(
    "rs_state, reopen_enabled, close_enabled, initial_processed_alerts, expect_reopen, expected_close_reason",
    [
        pytest.param("READ", True, False, ["alert-1"], True, None, id="open_reopen_enabled"),
        pytest.param("FALSE_POSITIVE", False, True, [], False, "False Positive", id="close_false_positive"),
    ],
)
def test_get_remote_data_command(
    mocker, mock_client, rs_state, reopen_enabled, close_enabled, initial_processed_alerts, expect_reopen, expected_close_reason
):
    """
    Given:
    - An RS alert with various states and enabled/disabled reopen/close settings.
    - processed_alerts pre-populated for reopen scenarios (alert must have been closed first).

    When:
    - get_remote_data_command is called.

    Then:
    - mirrored_object contains the raw alert state.
    - Reopen/close entries are added (with correct reason) when enabled; none when disabled.
    - NEW state never triggers any entry.
    """
    from GoogleThreatIntelligenceRSAlerts import get_remote_data_command

    mocker.patch.object(
        mock_client,
        "get_alert",
        return_value={"name": "projects/test-project/alerts/alert-1", "state": rs_state},
    )
    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = {
        "reopen_incident_for_open_alert_status": reopen_enabled,
        "close_incident_for_close_alert_status": close_enabled,
    }
    mock_demisto.getIntegrationContext.return_value = {"processed_alerts": initial_processed_alerts}

    result = get_remote_data_command(mock_client, {"id": "alert-1", "lastUpdate": "0"})

    assert result.mirrored_object.get("state") == rs_state
    has_reopen = any(e.get("Contents", {}).get("dbotIncidentReopen") is True for e in result.entries)
    assert has_reopen == expect_reopen
    close_entries = [e for e in result.entries if e.get("Contents", {}).get("dbotIncidentClose") is True]
    if expected_close_reason:
        assert len(close_entries) == 1
        assert close_entries[0]["Contents"]["closeReason"] == expected_close_reason
    else:
        assert close_entries == []


def test_get_modified_remote_data_returns_alert_ids(mocker, mock_client):
    """
    Given:
    - A single-page alert list response with two alerts.

    When:
    - get_modified_remote_data_command is called with a last_update timestamp.

    Then:
    - The response contains the two alert IDs extracted from the alert names.
    """
    from GoogleThreatIntelligenceRSAlerts import get_modified_remote_data_command

    mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto").debug = lambda *_: None

    alerts_response = {
        "alerts": [
            {"name": "projects/test-project/alerts/alert-modified-1", "state": "READ"},
            {
                "name": "projects/test-project/alerts/alert-modified-2",
                "state": "RESOLVED",
                "audit": {"updateTime": "2026-01-02T00:00:00Z"},
            },
        ]
    }
    mocker.patch.object(mock_client, "get_alert_list", return_value=alerts_response)

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-01-01T00:00:00Z"})

    assert isinstance(result, GetModifiedRemoteDataResponse)
    assert set(result.modified_incident_ids) == {"alert-modified-1", "alert-modified-2"}


@pytest.mark.parametrize(
    "alerts_list, expected_ids",
    [
        pytest.param([], [], id="empty_alerts"),
        pytest.param(
            [
                {"name": "projects/p/alerts/alert-no-ts-1"},
                {"name": "projects/p/alerts/alert-no-ts-2"},
            ],
            ["alert-no-ts-1", "alert-no-ts-2"],
            id="no_updatetime_on_last_alert_breaks_at_timestamp_check",
        ),
    ],
)
def test_get_modified_remote_data_empty_response(mocker, mock_client, alerts_list, expected_ids):
    """
    Given:
    - An alert list endpoint that returns no alerts, or alerts without audit.updateTime.

    When:
    - get_modified_remote_data_command is called.

    Then:
    - The response contains only the expected IDs (empty if no alerts).
    """
    from GoogleThreatIntelligenceRSAlerts import get_modified_remote_data_command

    mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto").debug = lambda *_: None
    mocker.patch.object(mock_client, "get_alert_list", return_value={"alerts": alerts_list})

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-01-01T00:00:00Z"})

    assert set(result.modified_incident_ids) == set(expected_ids)


def test_get_modified_remote_data_caps_at_max_mirroring_limit(mocker, mock_client):
    """
    Given:
    - A response with more alerts than MAX_MIRRORING_LIMIT.

    When:
    - get_modified_remote_data_command is called.

    Then:
    - The returned list length does not exceed MAX_MIRRORING_LIMIT.
    """
    from GoogleThreatIntelligenceRSAlerts import get_modified_remote_data_command

    mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto").debug = lambda *_: None

    page_size = 1000
    page1_alerts = [{"name": f"projects/p/alerts/alert-p1-{i}"} for i in range(page_size)]
    page1_alerts[-1]["audit"] = {"updateTime": "2026-01-02T00:00:00Z"}  # type: ignore

    page2_alerts = [{"name": f"projects/p/alerts/alert-p2-{i}"} for i in range(MAX_MIRRORING_LIMIT + 10)]
    page2_alerts[-1]["audit"] = {"updateTime": "2026-01-03T00:00:00Z"}  # type: ignore

    mocker.patch.object(
        mock_client,
        "get_alert_list",
        side_effect=[{"alerts": page1_alerts}, {"alerts": page2_alerts}],
    )

    result = get_modified_remote_data_command(mock_client, {"lastUpdate": "2026-01-01T00:00:00Z"})

    assert len(result.modified_incident_ids) == MAX_MIRRORING_LIMIT


@pytest.mark.parametrize(
    "incident_status_str, delta_state, extra_delta, params_return, processed_alerts_init, expected_api_action",
    [
        pytest.param(
            None,
            "Read",
            {},
            {},
            [],
            "read",
            id="active_status_delta_read",
        ),
        pytest.param(
            None,
            None,
            {},
            {"alert_status_for_incident_closure": "Resolved"},
            [],
            "resolve",
            id="done_status_closure_resolved",
        ),
        pytest.param(
            "ACTIVE",
            None,
            {"closingUserId": ""},
            {"alert_status_for_incident_reopen": "Escalated"},
            ["alert-abc"],
            "escalate",
            id="active_status_reopen_escalated",
        ),
    ],
)
def test_update_remote_system_maps_all_xsoar_states(
    mocker, mock_client, incident_status_str, delta_state, extra_delta, params_return, processed_alerts_init, expected_api_action
):
    """
    Given:
    - Various gtirsalertstate delta values, DONE incident status, or ACTIVE reopen status.

    When:
    - update_remote_system_command is called with incident_changed=True.

    Then:
    - client.update_alert_status is called with the correct API action.
    """
    from CommonServerPython import IncidentStatus
    from GoogleThreatIntelligenceRSAlerts import update_remote_system_command

    mock_update = mocker.patch.object(mock_client, "update_alert_status")
    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = params_return
    mock_demisto.getIntegrationContext.return_value = {"processed_alerts": processed_alerts_init}

    if incident_status_str is None:
        incident_status_str = (
            str(IncidentStatus.DONE) if "alert_status_for_incident_closure" in params_return else str(IncidentStatus.ACTIVE)
        )
    elif incident_status_str == "ACTIVE":
        incident_status_str = str(IncidentStatus.ACTIVE)
    elif incident_status_str == "DONE":
        incident_status_str = str(IncidentStatus.DONE)

    delta_dict = {"gtirsalertstate": delta_state} if delta_state else {}
    delta_dict.update(extra_delta)
    delta = json.dumps(delta_dict)

    args = {
        "remoteId": "alert-abc",
        "status": incident_status_str,
        "delta": delta,
        "incidentChanged": "true",
        "data": json.dumps({}),
        "entries": json.dumps([]),
    }

    update_remote_system_command(mock_client, args)

    mock_update.assert_called_once_with("alert-abc", expected_api_action)


@pytest.mark.parametrize(
    "args_override, expected_result, params_override, processed_alerts_init",
    [
        pytest.param(
            {"incidentChanged": "false", "remoteId": "alert-xyz"},
            "alert-xyz",
            {},
            [],
            id="incident_not_changed",
        ),
        pytest.param(
            {"remoteId": "", "incidentChanged": "true"},
            "",
            {},
            [],
            id="empty_remote_id",
        ),
        pytest.param(
            {"status": "not-a-number", "incidentChanged": "true"},
            "alert-xyz",
            {},
            [],
            id="invalid_status_string",
        ),
        pytest.param(
            {"delta": "not-valid-json", "incidentChanged": "true"},
            "alert-xyz",
            {},
            [],
            id="invalid_delta_json",
        ),
        pytest.param(
            {"delta": {}, "incidentChanged": "true"},
            "alert-xyz",
            {},
            [],
            id="dict_delta_no_gtirsalertstate",
        ),
        pytest.param(
            {"delta": json.dumps({"gtirsalertstate": "InvalidState"}), "incidentChanged": "true"},
            "alert-xyz",
            {},
            [],
            id="invalid_rs_state_in_delta",
        ),
        pytest.param(
            {"incidentChanged": "true"},
            "alert-xyz",
            {"alert_status_for_incident_closure": "InvalidAlterStatus"},
            [],
            id="done_status_invalid_closure_status",
        ),
        pytest.param(
            {"incidentChanged": "true"},
            "alert-xyz",
            {"alert_status_for_incident_reopen": "InvalidReopen"},
            ["alert-xyz"],
            id="active_status_invalid_reopen_status",
        ),
        pytest.param(
            {"incidentChanged": "true", "delta": json.dumps({"closingUserId": ""})},
            "alert-xyz",
            {"alert_status_for_incident_reopen": "InvalidReopen"},
            ["alert-xyz"],
            id="reopen_with_invalid_alert_status_for_incident_reopen",
        ),
    ],
)
def test_update_remote_system_skips_update(
    mocker, mock_client, args_override, expected_result, params_override, processed_alerts_init
):
    """
    Given:
    - Various conditions that should prevent an API call:
      incident_changed=False, empty remoteId, invalid status string, invalid delta JSON,
      dict delta, invalid RS state, DONE status with invalid alert_status_for_incident_closure,
      or ACTIVE reopen with invalid alert_status_for_incident_reopen.

    When:
    - update_remote_system_command is called.

    Then:
    - client.update_alert_status is never called and the remote ID is returned.
    """
    from CommonServerPython import IncidentStatus
    from GoogleThreatIntelligenceRSAlerts import update_remote_system_command

    mock_update = mocker.patch.object(mock_client, "update_alert_status")
    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = params_override
    mock_demisto.getIntegrationContext.return_value = {"processed_alerts": processed_alerts_init}

    base_args = {
        "remoteId": "alert-xyz",
        "status": str(IncidentStatus.DONE)
        if params_override.get("alert_status_for_incident_closure")
        else str(IncidentStatus.ACTIVE),
        "delta": json.dumps({}),
        "incidentChanged": "true",
        "data": json.dumps({}),
        "entries": json.dumps([]),
    }
    base_args.update(args_override)

    result = update_remote_system_command(mock_client, base_args)

    mock_update.assert_not_called()
    assert result == expected_result


def test_fetch_incidents_includes_mirror_params(mocker, mock_client, requests_mock):
    """
    Given:
    - An alert list response with one alert.
    - mirror_direction is set to "Outgoing".

    When:
    - fetch_incidents is called.

    Then:
    - Each incident's rawJSON contains mirror_direction, mirror_instance, and mirror_id.
    """
    from GoogleThreatIntelligenceRSAlerts import fetch_incidents

    alerts_response = util_load_json("test_data/alert_list.json")

    list_url = f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}"
    requests_mock.get(list_url, json=alerts_response, status_code=200)

    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = {"mirror_direction": "Outgoing"}
    mock_demisto.integrationInstance.return_value = "test-instance"
    mock_demisto.debug = lambda *_: None

    params = {
        "first_fetch": "3 days",
        "max_fetch": "10",
        "mirror_direction": "Outgoing",
    }

    incidents, _ = fetch_incidents(mock_client, {}, params)

    assert len(incidents) > 0
    for inc in incidents:
        raw = json.loads(inc["rawJSON"])
        assert raw.get("mirror_direction") == "Out"
        assert raw.get("mirror_instance") == "test-instance"
        assert "mirror_id" in raw


def test_main_dispatches_mirror_commands(mocker, requests_mock):
    """
    Given:
    - The get-remote-data and update-remote-system commands.

    When:
    - main is invoked for each.

    Then:
    - Each command calls return_results with the expected value.
    """
    from CommonServerPython import IncidentStatus
    from GoogleThreatIntelligenceRSAlerts import main

    mocker.patch("GoogleThreatIntelligenceRSAlerts.get_integration_context", return_value={"access_token": "tok"})
    mocker.patch("GoogleThreatIntelligenceRSAlerts.set_integration_context")

    # --- get-remote-data ---
    mock_demisto = mocker.patch("GoogleThreatIntelligenceRSAlerts.demisto")
    mock_demisto.params.return_value = {
        "server_url": BASE_URL,
        "credentials": {"password": "test_api_key"},
        "project_id": "test_project",
        "insecure": False,
        "proxy": False,
        "mirror_direction": "Incoming",
        "reopen_incident_for_open_alert_status": True,
        "close_incident_for_close_alert_status": True,
    }
    mock_demisto.command.return_value = "get-remote-data"
    mock_demisto.args.return_value = {"id": "alert-1", "lastUpdate": "0"}
    mock_demisto.integrationInstance.return_value = "test-instance"
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['ALERT_GET'].format('test_project', 'alert-1')}",
        json={"name": "projects/test_project/alerts/alert-1", "state": "READ"},
        status_code=200,
    )
    mock_return = mocker.patch("GoogleThreatIntelligenceRSAlerts.return_results")
    mocker.patch("GoogleThreatIntelligenceRSAlerts.return_error")
    main()
    mock_return.assert_called_once()

    # --- update-remote-system ---
    mock_demisto.params.return_value = {
        "server_url": BASE_URL,
        "credentials": {"password": "test_api_key"},
        "project_id": "test_project",
        "insecure": False,
        "proxy": False,
        "alert_status_for_incident_closure": "Resolved",
    }
    mock_demisto.command.return_value = "update-remote-system"
    mock_demisto.args.return_value = {
        "remoteId": "alert-out-1",
        "status": str(IncidentStatus.ACTIVE),
        "delta": json.dumps({}),
        "incidentChanged": "false",
        "data": json.dumps({}),
        "entries": json.dumps([]),
    }
    mock_return.reset_mock()
    main()
    mock_return.assert_called_once_with("alert-out-1")

    # --- fetch-incidents ---
    mock_demisto.params.return_value = {
        "server_url": BASE_URL,
        "credentials": {"password": "test_api_key"},
        "project_id": "test_project",
        "insecure": False,
        "proxy": False,
        "first_fetch": "3 days",
        "max_fetch": "10",
    }
    mock_demisto.command.return_value = "fetch-incidents"
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['ALERT_LIST'].format('test_project')}",
        json={"alerts": []},
        status_code=200,
    )
    mock_return.reset_mock()
    main()
    mock_demisto.incidents.assert_called_once_with([])
    mock_demisto.setLastRun.assert_called_once()

    # --- get-modified-remote-data ---
    mock_demisto.command.return_value = "get-modified-remote-data"
    mock_demisto.args.return_value = {"lastUpdate": "2026-01-01T00:00:00Z"}
    mock_return.reset_mock()
    main()
    mock_return.assert_called_once()

    # --- gti-rs-alert-list (generic command) ---
    mock_demisto.command.return_value = "gti-rs-alert-list"
    mock_demisto.args.return_value = {}
    mock_return.reset_mock()
    main()
    mock_return.assert_called_once()

import json
import os
from unittest.mock import MagicMock

import pytest

from MicrosoftGraphAPI import MsGraphClient, generic_command
from MicrosoftApiModule import AZURE_WORLDWIDE_CLOUD


def load_test_data(test_data_filename):
    with open(os.path.join("./test_data", test_data_filename)) as f:
        return json.load(f)


@pytest.fixture()
def client(requests_mock):
    requests_mock.post(
        "https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token",
        json={},
    )
    return MsGraphClient(
        app_id="app_id",
        scope="Application.Read.All",
        app_secret="app_secret",
        tenant_id="tenant_id",
        verify=False,
        proxy=False,
        azure_cloud=AZURE_WORLDWIDE_CLOUD,
        auth_code="",
        redirect_uri="",
    )


def test_generic_command_positive_value_key(requests_mock, client):
    """
    Given:
        - API resource /applications
    When:
        - Running the generic command
    Then:
        - Ensure outputs are as expected
    """
    applications_res = load_test_data("applications.json")
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/applications?$top=10",
        json=applications_res,
    )
    args = {
        "resource": "/applications",
        "odata": "$top=10",
    }
    res = generic_command(client, args)
    assert res.outputs == applications_res.get("value")


def test_generic_command_with_boolean_value(requests_mock, client):
    """
    Given:
        - API resource /users/testUser/revokeSignInSessions
    When:
        - Running the generic command
    Then:
        - Ensure Human readable returns
    """
    # Example response returned from the API for this resource
    res = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Edm.Boolean", "value": True}
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/users/testUser/revokeSignInSessions",
        json=res,
    )
    args = {
        "resource": "/users/testUser/revokeSignInSessions",
    }
    res = generic_command(client, args)
    assert res.readable_output == "The API query ran successfully and returned no content."


def test_generic_command_positive_other_key(requests_mock, client):
    """
    Given:
        - API resource /applications
        - API returns data under other key than value
    When:
        - Running the generic command
    Then:
        - Ensure outputs are as expected
    """
    applications_res = load_test_data("applications.json")
    value = applications_res["value"]
    applications_res["not_value"] = value
    applications_res.pop("value", None)
    requests_mock.get(
        "https://graph.microsoft.com/v1.0/applications?$top=10",
        json=applications_res,
    )
    args = {
        "resource": "/applications",
        "odata": "$top=10",
    }
    res = generic_command(client, args)
    assert res.outputs["not_value"][0] == value[0]


def test_generic_command_no_content(requests_mock, client):
    """
    Given:
        - API resource /identityProtection/riskyUsers/dismiss
        - no_content set to `true`
    When:
        - Running the generic command
    Then:
        - Ensure the command does not fail on no content response
    """
    requests_mock.post(
        "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss",
        text="",
    )
    args = {
        "http_method": "POST",
        "resource": "/identityProtection/riskyUsers/dismiss",
        "no_content": "true",
        "populate_context": "false",
    }
    res = generic_command(client, args)
    assert res


@pytest.mark.parametrize(
    "params",
    [
        {"app_id": "app_id", "tenant_id": "tenant_id", "credentials": {"password": "password"}},
        {"app_id": "app_id", "tenant_id": "tenant_id", "app_secret": "password"},
    ],
)
def test_test_module(mocker, params):
    """
    Given:
        - Parameter credentials instead of the app_secret (in self-deployed mode).
    When:
        - Running the test-module command.
    Then:
        - Ensure the command doesn't fail on ValueError (as for device-flow mode).
    """
    from MicrosoftGraphAPI import demisto, main, MicrosoftClient

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(MicrosoftClient, "get_access_token")
    mocker.patch.object(demisto, "results")

    main()

    result = demisto.results.call_args[0][0]
    assert result == "ok"


@pytest.mark.parametrize(argnames="client_id", argvalues=["test_client_id", None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
        - Managed Identities client id for authentication.
    When:
        - Calling test_module.
    Then:
        - Ensure the output are as expected.
    """

    from MicrosoftGraphAPI import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import MicrosoftGraphAPI
    import demistomock as demisto

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {"managed_identities_client_id": {"password": client_id}, "use_managed_identities": "True"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(MicrosoftGraphAPI, "return_results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in MicrosoftGraphAPI.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.graph]
    assert client_id and qs["client_id"] == [client_id] or "client_id" not in qs


@pytest.mark.parametrize(
    "headers, expected_headers",
    [
        ("ConsistencyLevel:eventual,User-Agent:MyApp/1.0", {"ConsistencyLevel": "eventual", "User-Agent": "MyApp/1.0"}),
        (None, None),  # No headers case
    ],
)
def test_generic_command_headers(headers, expected_headers):
    client = MagicMock(spec=MsGraphClient)
    client.generic_request = MagicMock(return_value={"response": "success"})

    args = {
        "resource": "/test/resource",
        "http_method": "GET",
        "api_version": "v1.0",
        "headers": headers,
        "request_body": json.dumps({"key": "value"}),
    }

    generic_command(client, args)

    client.generic_request.assert_called_once_with(
        resource="/test/resource",
        http_method="GET",
        api_version="v1.0",
        odata="",
        request_body={"key": "value"},
        headers=expected_headers,
    )

import pytest
import json
from AzureSecurityCenter_v2 import (
    MsClient,
    get_aps_command,
    get_atp_command,
    get_secure_scores_command,
    update_atp_command,
    get_alert_command,
    list_alerts_command,
)

with open("./test_data/integration_test_data.json") as f:
    data = json.load(f)

RAW_RESPONSES = data.get("RAW_RESPONSES")
COMMAND_OUTPUTS = data.get("COMMAND_OUTPUTS")

client = MsClient(
    server="url",
    tenant_id="tenant",
    auth_id="auth_id",
    enc_key="enc_key",
    app_name="APP_NAME",
    verify="verify",
    proxy="proxy",
    self_deployed="self_deployed",
    subscription_id="subscription_id",
    ok_codes=(1, 3),
    certificate_thumbprint=None,
    private_key=None,
)


def test_get_atp_command(mocker):
    mocker.patch.object(client, "get_atp", return_value=RAW_RESPONSES["GET_ATP_COMMAND_RAW_RESPONSE"])
    args = {"resource_group_name": "test", "setting_name": "test", "storage_account": "test"}
    _, ec, _ = get_atp_command(client, args)
    assert ec == COMMAND_OUTPUTS["EXPECTED_GET_ATP_COMMAND_CONTEXT"]


def test_update_atp_command(mocker):
    mocker.patch.object(client, "update_atp", return_value=RAW_RESPONSES["UPDATE_ATP_RAW"])
    args = {"resource_group_name": "test", "setting_name": "test", "is_enabled": "test", "storage_account": "test"}
    _, ec, _ = update_atp_command(client, args)
    assert ec == COMMAND_OUTPUTS["EXPECTED_UPDATE_ATP_CONTEXT"]


def test_get_aps_command(mocker):
    mocker.patch.object(client, "get_aps", return_value=RAW_RESPONSES["GET_APS_RAW_RESPONSE"])
    args = {"setting_name": "test"}
    _, ec, _ = get_aps_command(client, args)
    assert ec == COMMAND_OUTPUTS["EXPECTED_GET_APS_CONTEXT"]


def test_get_secure_score_command(mocker):
    mocker.patch.object(client, "get_secure_scores", return_value=RAW_RESPONSES["GET_SECURE_SCORE_RAW_RESPONSE"])
    args = {"secure_score_name": "ascScore"}
    _, ec, _ = get_secure_scores_command(client, args)
    assert ec == COMMAND_OUTPUTS["EXPECTED_GET_SECURE_SCORE_CONTEXT"]


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

    import re

    import demistomock as demisto
    from AzureSecurityCenter_v2 import MANAGED_IDENTITIES_TOKEN_URL, Resources, main

    mock_token = {"access_token": "test_token", "expires_in": "86400"}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    requests_mock.get(re.compile(f"^{Resources.management_azure}.*"), json={"value": []})

    params = {
        "managed_identities_client_id": {"password": client_id},
        "use_managed_identities": "True",
        "resource_group": "test_resource_group",
        "server_url": Resources.management_azure,
        "credentials_auth_id": {"password": "example"},
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "results", return_value=params)
    mocker.patch("MicrosoftApiModule.get_integration_context", return_value={})

    main()

    assert "ok" in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs["resource"] == [Resources.management_azure]
    assert (client_id and qs["client_id"] == [client_id]) or "client_id" not in qs


def test_get_alert_command(mocker):
    mocker.patch.object(client, "get_alert", return_value=RAW_RESPONSES["GET_ALERT_RAW_RESPONSE"])
    args = {"asc_location": "loc", "alert_id": "123"}
    output = get_alert_command(client, args)
    ec = output[0]["EntryContext"]
    assert ec == COMMAND_OUTPUTS["EXPECTED_GET_ALERT_CONTEXT"]


def test_list_alerts_command(mocker):
    mocker.patch.object(client, "list_alerts", return_value=RAW_RESPONSES["LIST_ALERTS_RAW_RESPONSE"])
    args = {"asc_location": "loc"}
    _, ec, _ = list_alerts_command(client, args)
    assert ec == COMMAND_OUTPUTS["EXPECTED_LIST_ALERTS_CONTEXT"]

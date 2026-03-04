import json

import CheckPointFirewallV2
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


SERVER_URL = "www.example.com"
HTTPS_WWW_BASE_URL = f"https://{SERVER_URL}"


def test_checkpoint_login_and_get_session_id(requests_mock):
    """
    Given
        a client object
    When
        calling login_and_get_session_id
    Then
        validate 4xx, 5xx response status codes raise a DemistoException
    """

    sid = "sid_value"
    login_args = {"username": "user", "password": "pass", "session_timeout": 600, "domain_arg": "domain"}

    raw_response = {"sid": sid}
    requests_mock.post(f"{HTTPS_WWW_BASE_URL}/login", json=raw_response)

    client = CheckPointFirewallV2.Client(base_url=HTTPS_WWW_BASE_URL, use_ssl=False, use_proxy=False)
    assert client.headers == {"Content-Type": "application/json"}  # before login, sid is not present

    command_result = client.login(**login_args)
    assert command_result.to_context() == {
        "Type": 1,
        "ContentsFormat": "json",
        "Contents": {"sid": sid},
        "HumanReadable": f"### CheckPoint session data:\n|session-id|\n|---|\n| {sid} |\n",
        "EntryContext": {"CheckPoint.Login(val.uid && val.uid == obj.uid)": {"session-id": sid}},
        "IndicatorTimeline": [],
        "IgnoreAutoExtract": False,
        "Note": False,
        "Relationships": [],
    }
    assert client.headers == {"Content-Type": "application/json", "X-chkp-sid": sid}  # after login, sid is present
    assert client.has_performed_login
    assert client.sid == sid  # a non-None client.sid indicates that the client is logged in.


INTEGRATION_CONTEXT_EMPTY = {}
INTEGRATION_CONTEXT_WITH_SID = {"cp_sid": "sid"}


@pytest.mark.parametrize(
    "session_id,integration_context,should_log_in",
    (
        (None, INTEGRATION_CONTEXT_EMPTY, True),
        ("None", INTEGRATION_CONTEXT_EMPTY, True),
        ("sid", INTEGRATION_CONTEXT_EMPTY, False),
        (None, INTEGRATION_CONTEXT_WITH_SID, False),
        ("None", INTEGRATION_CONTEXT_WITH_SID, False),
        ("sid", INTEGRATION_CONTEXT_WITH_SID, False),
    ),
)
def test_checkpoint_login_mechanism(mocker, session_id, integration_context, should_log_in):
    """
    Given
        an session id argument
    When
        calling an arbitrary command, that is not an explicit login command
    Then
        validate a login is performed if and only if the session id is in {None, "None"} AND integrationContext is empty
    """
    from CheckPointFirewallV2 import main

    port = 4434

    mocker.patch.object(CheckPointFirewallV2.demisto, "getIntegrationContext", return_value=integration_context)
    mocker.patch.object(CheckPointFirewallV2.demisto, "command", return_value="checkpoint-host-add")
    mocker.patch.object(
        CheckPointFirewallV2.demisto,
        "args",
        return_value={
            "session_id": session_id,
            "name": "george",
            "ip_address": "0.0.0.0",
            "groups": [],
            "ignore_warnings": "true",
            "ignore_errors": "false",
        },
    )
    mocker.patch.object(
        CheckPointFirewallV2.demisto,
        "params",
        return_value={
            "username": {"identifier": "user", "password": "pass"},
            "session_timeout": 601,
            "domain_arg": "domain",
            "server": SERVER_URL,
            "port": port,
        },
    )
    mocked_address = f"{HTTPS_WWW_BASE_URL}:{port}/web_api"

    import requests_mock

    with requests_mock.Mocker() as request_mocker:
        login_adapter = request_mocker.post(f"{mocked_address}/login", json={"sid": "sid"})
        add_host_adapter = request_mocker.post(f"{mocked_address}/add-host", json={})
        logout_adapter = request_mocker.post(f"{mocked_address}/logout", json={})

        main()

        assert login_adapter.call_count == int(should_log_in)
        assert add_host_adapter.call_count == 1
        assert logout_adapter.call_count == int(should_log_in)


@pytest.mark.parametrize("response_code", [418, 500])
def test_checkpoint_login_and_get_session_id__invalid(requests_mock, response_code):
    """
    Given
        a client object
    When
        calling login_and_get_session_id
    Then
        validate 4xx, 5xx response status codes raise a DemistoException
    """

    login_args = {"username": "user", "password": "pass", "session_timeout": 600, "domain_arg": "domain"}

    requests_mock.post(f"{HTTPS_WWW_BASE_URL}/login", status_code=response_code, json={})

    client = CheckPointFirewallV2.Client(base_url=HTTPS_WWW_BASE_URL, use_ssl=False, use_proxy=False)
    with pytest.raises(CheckPointFirewallV2.DemistoException) as e:
        client.login(**login_args)
    assert e.value.res.status_code == response_code
    assert not client.has_performed_login


def test_checkpoint_test_connection_command__500(requests_mock):
    """
    Given
        a client object
    When
        calling test_module
    Then
        validate a status-code 500 is handled correctly
    """
    requests_mock.post(
        f"{HTTPS_WWW_BASE_URL}/show-api-versions",
        status_code=500,
        json={"message": "this is an error message", "warnings": ["dummy_warning"], "errors": ["dummy_error"]},
    )
    client = CheckPointFirewallV2.Client(base_url=HTTPS_WWW_BASE_URL, use_ssl=False, use_proxy=False)
    assert client.test_connection() == "Server Error: make sure Server URL and Server Port are correctly set"
    assert not client.has_performed_login


def test_checkpoint_test_connection_command__not_logged_in(requests_mock):
    """
    Given
        a client object that is not logged in
    When
        calling test_module
    Then
        validate the relevant message is shown to the user
    """

    base_url = f"https://{SERVER_URL}"
    requests_mock.post(f"{base_url}/show-api-versions", json={"message": "Missing header: [X-chkp-sid]"})
    client = CheckPointFirewallV2.Client(base_url=base_url, use_ssl=False, use_proxy=False)
    assert client.test_connection() == "\nWrong credentials! Please check the username and password you entered and try again."
    assert not client.has_performed_login


def test_checkpoint_list_hosts_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_hosts_command

    mock_response = util_load_json("test_data/list_host_response.json")
    mocked_client = mocker.Mock()
    mocked_client.list_hosts.return_value = mock_response

    result = checkpoint_list_hosts_command(mocked_client, 50, 0).outputs
    assert result[0].get("name") == "list 1"
    assert result[0].get("uid") == "123"
    assert result[0].get("type") == "host"
    assert len(result[0]) == 11


def test_checkpoint_get_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_get_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_host_response.json")
    mocked_client.get_host.return_value = mock_response
    result = checkpoint_get_host_command(mocked_client, "host 1").outputs
    assert result.get("name") == "host 1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "host"
    assert len(result) == 12


def test_checkpoint_add_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response
    result = checkpoint_add_host_command(mocked_client, "host 1", "1.2.3.4", False, False).outputs
    assert result[0].get("name") == "add host"
    assert result[0].get("uid") == "123"
    assert result[0].get("type") == "host"
    assert len(result[0]) == 14


def test_checkpoint_update_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response
    result = checkpoint_update_host_command(mocked_client, "host 1", False, False).outputs
    assert result.get("name") == "update host"
    assert result.get("uid") == "123"
    assert result.get("type") == "host"
    assert len(result) == 12


def test_checkpoint_delete_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_host_command

    mocked_client = mocker.Mock()
    mocked_client.delete_host.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_host_command(mocked_client, "host 1", False, False).outputs
    assert result.get("message") == "OK"
    assert mocked_client.delete_host.call_args[0][0] == "host 1"


def test_checkpoint_list_groups_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_groups_command

    mock_response = util_load_json("test_data/list_groups.json")
    mocked_client = mocker.Mock()
    mocked_client.list_groups.return_value = mock_response
    result = checkpoint_list_groups_command(mocked_client, 2, 0).outputs
    assert result[0].get("name") == "group1"
    assert result[0].get("uid") == "123"
    assert result[0].get("type") == "group"
    assert len(result[0]) == 11


def test_checkpoint_get_group_command(mocker):
    from CheckPointFirewallV2 import checkpoint_get_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_group.json")
    mocked_client.get_group.return_value = mock_response
    result = checkpoint_get_group_command(mocked_client, "group_test").outputs
    assert result.get("name") == "group_test"


def test_checkpoint_add_group_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_group.json")
    mocked_client.add_group.return_value = mock_response
    result = checkpoint_add_group_command(mocked_client, "groupi").outputs
    assert result.get("name") == "groupi"
    assert result.get("uid") == "1234"
    assert result.get("type") == "group"
    assert len(result) == 14


def test_checkpoint_update_group_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_group.json")
    mocked_client.update_group.return_value = mock_response
    result = checkpoint_update_group_command(mocked_client, "groupi", False, False).outputs
    assert result.get("name") == "group_test"
    assert result.get("uid") == "1234"
    assert result.get("type") == "group"
    assert len(result) == 11


def test_checkpoint_delete_group_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_group_command

    mocked_client = mocker.Mock()
    mocked_client.delete_group.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_group_command(mocked_client, "group").outputs
    assert result.get("message") == "OK"


def test_checkpoint_list_application_site_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_application_site_command

    mock_response = util_load_json("test_data/list_application_site.json")
    mocked_client = mocker.Mock()
    mocked_client.list_application_site.return_value = mock_response
    result = checkpoint_list_application_site_command(mocked_client, 2, 0).outputs
    assert result[0].get("name") == "application site 1"
    assert result[0].get("uid") == "1234"
    assert result[0].get("type") == "application-site"
    assert len(result[0]) == 11


def test_checkpoint_add_application_site_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_application_site.json")
    mocked_client.add_application_site.return_value = mock_response
    result = checkpoint_add_application_site_command(mocked_client, "application1", "Test Category", "qmasters.co").outputs
    assert result.get("name") == "application1"
    assert result.get("uid") == "1234"
    assert result.get("url-list") == ["qmasters.co"]
    assert result.get("type") == "application-site"
    assert len(result) == 12


def test_checkpoint_update_application_site_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_application_site.json")
    mocked_client.update_application_site.return_value = mock_response
    result = checkpoint_update_application_site_command(mocked_client, "app1", False).outputs
    assert result.get("name") == "application1"
    assert result.get("uid") == "1234"
    assert result.get("url-list") == ["paloaltonetworks.com"]
    assert result.get("type") == "application-site"
    assert len(result) == 11


def test_checkpoint_delete_application_site_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_application_site_command

    mocked_client = mocker.Mock()
    mocked_client.delete_application_site.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_application_site_command(mocked_client, "application1").outputs
    assert result.get("message") == "OK"


def test_checkpoint_list_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_address_range_command

    mock_response = util_load_json("test_data/list_address_range.json")
    mocked_client = mocker.Mock()
    mocked_client.list_address_ranges.return_value = mock_response
    result = checkpoint_list_address_range_command(mocked_client, 2, 0).outputs
    assert result[0].get("name") == "address_range_test_1"
    assert result[0].get("uid") == "1234"
    assert result[0].get("type") == "address-range"
    assert len(result[0]) == 11


def test_checkpoint_get_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_get_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_address_range.json")
    mocked_client.get_address_range.return_value = mock_response
    result = checkpoint_get_address_range_command(mocked_client, "address_range_1").outputs
    assert result.get("name") == "address_range_1"


def test_checkpoint_add_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_address_range.json")
    mocked_client.add_address_range.return_value = mock_response
    result = checkpoint_add_address_range_command(
        mocked_client, "address_range_1", "255.255.255.32", "255.255.255.64", False, False, False
    ).outputs
    assert result.get("name") == "address_range_1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "address-range"
    assert len(result) == 15


def test_checkpoint_update_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_address_range.json")
    mocked_client.update_address_range.return_value = mock_response
    result = checkpoint_update_address_range_command(mocked_client, "address_range_1", False, False).outputs
    assert result.get("name") == "address_range_1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "address-range"
    assert len(result) == 12


def test_checkpoint_delete_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_address_range_command

    mocked_client = mocker.Mock()
    mocked_client.delete_address_range.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_address_range_command(mocked_client, "address_range_1").outputs
    assert result.get("message") == "OK"


def test_checkpoint_list_threat_indicator_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_threat_indicator_command

    mock_response = util_load_json("test_data/list_threat_indicator.json")
    mocked_client = mocker.Mock()
    mocked_client.list_threat_indicators.return_value = mock_response
    result = checkpoint_list_threat_indicator_command(mocked_client, 5, 0).outputs
    assert result[2].get("name") == "threat_indicator_3"
    assert result[2].get("uid") == "9101"
    assert result[2].get("type") == "threat-indicator"
    assert len(result[2]) == 11


def test_checkpoint_get_threat_indicator_command(mocker):
    from CheckPointFirewallV2 import checkpoint_get_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_threat_indicator.json")
    mocked_client.get_threat_indicator.return_value = mock_response
    result = checkpoint_get_threat_indicator_command(mocked_client, "threat_indicator_1").outputs
    assert result.get("name") == "threat_indicator_1"


def test_checkpoint_add_threat_indicator_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_threat_indicator.json")
    mocked_client.add_threat_indicator.return_value = mock_response
    result = checkpoint_add_threat_indicator_command(
        mocked_client, "threat_indicator_1", profile_action="Standard Threat Prevention_prevent", observables=[]
    ).outputs
    assert result.get("task-id") == "123456789"


def test_checkpoint_update_threat_indicator_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_threat_indicator.json")
    mocked_client.update_threat_indicator.return_value = mock_response
    result = checkpoint_update_threat_indicator_command(
        mocked_client, "address_range_1", profile_action="Standard Threat Prevention_prevent"
    ).outputs
    assert result.get("name") == "threat_indicator_1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "threat-indicator"
    assert len(result) == 11


def test_checkpoint_delete_threat_indicator_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_threat_indicator_command

    mocked_client = mocker.Mock()
    mocked_client.delete_threat_indicator.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_threat_indicator_command(mocked_client, "threat_indicator_1").outputs
    assert result.get("message") == "OK"


def test_checkpoint_list_access_rule_command(mocker):
    from CheckPointFirewallV2 import checkpoint_list_access_rule_command

    mock_response = util_load_json("test_data/list_access_rule.json")
    mocked_client = mocker.Mock()
    mocked_client.list_access_rule.return_value = mock_response
    result = checkpoint_list_access_rule_command(mocked_client, "Networks", 1, 0).outputs
    assert result[0].get("name") == "access_rule_1"
    assert result[0].get("uid") == "1234"
    assert result[0].get("type") == "access-rule"
    assert len(result[0]) == 11


def test_checkpoint_add_access_rule_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_rule.json")
    mocked_client.add_rule.return_value = mock_response
    result = checkpoint_add_access_rule_command(mocked_client, "access_rule_1", "Network", "top").outputs
    assert result.get("uid") == "1234"
    assert result.get("type") == "access-rule"
    assert len(result) == 10


def test_checkpoint_update_access_rule_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_rule.json")
    mocked_client.update_rule.return_value = mock_response
    result = checkpoint_update_access_rule_command(mocked_client, "access_rule_1", "Network", False, False, False).outputs
    assert result.get("name") == "access_rule_1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "access-rule"
    assert len(result) == 13


def test_checkpoint_delete_access_rule_command(mocker):
    from CheckPointFirewallV2 import checkpoint_delete_access_rule_command

    mocked_client = mocker.Mock()
    mocked_client.delete_rule.return_value = util_load_json("test_data/delete_object.json")
    result = checkpoint_delete_access_rule_command(mocked_client, "access_rule_1", "Network").outputs
    assert result.get("message") == "OK"


def test_publish_command(mocker):
    from CheckPointFirewallV2 import checkpoint_publish_command

    mocked_client = mocker.Mock()
    mocked_client.publish.return_value = util_load_json("test_data/publish.json")
    result = checkpoint_publish_command(mocked_client).outputs
    assert result.get("task-id") == "01234567"


def test_add_batch_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_objects_batch_command

    mocked_client = mocker.Mock()

    def validate_add_list(object_type, add_list):
        assert type(add_list) is list
        for obj in add_list:
            assert len(obj) == 2
            assert "name" in obj
            assert "ip-address" in obj

        return {}

    mocked_client.add_objects_batch.side_effect = validate_add_list
    checkpoint_add_objects_batch_command(mocked_client, "01234567", "1.1.1.1", "test")


def test_show_task_command(mocker):
    from CheckPointFirewallV2 import checkpoint_show_task_command

    mocked_client = mocker.Mock()
    mocked_client.show_task.return_value = util_load_json("test_data/show_task.json")
    result = checkpoint_show_task_command(mocked_client, "01234567").outputs
    assert result[0].get("task-id") == "01234567"
    assert result[0].get("task-name") == "Publish operation"
    assert result[0].get("status") == "succeeded"
    assert result[0].get("progress-percentage") == 100


@pytest.mark.parametrize("server", (SERVER_URL, f"https://{SERVER_URL}", f"{SERVER_URL}/", f"https://{SERVER_URL}/"))
def test_checkpoint_server_sanitization(mocker, server: str):
    """
    Given
        login arguments for a Client
    When
        calling `main()`
    Then
        validate the `server` value in the created Client is sanitized
        (left-trimming `https://` and right-trimming `/`)
    """
    import requests_mock
    from CheckPointFirewallV2 import main

    port = 4434
    mocker.patch.object(CheckPointFirewallV2.demisto, "getIntegrationContext", return_value={})
    mocker.patch.object(CheckPointFirewallV2.demisto, "command", return_value="checkpoint-host-add")
    mocker.patch.object(
        CheckPointFirewallV2.demisto,
        "args",
        return_value={
            "session_id": "session_id",
            "name": "george",
            "ip_address": "0.0.0.0",
            "groups": [],
            "ignore_warnings": "true",
            "ignore_errors": "false",
        },
    )
    mocker.patch.object(
        CheckPointFirewallV2.demisto,
        "params",
        return_value={
            "username": {"identifier": "user", "password": "pass"},
            "session_timeout": 601,
            "domain_arg": "domain",
            "server": server,
            "port": port,
        },
    )
    web_api_address = f"{HTTPS_WWW_BASE_URL}:{port}/web_api"

    with requests_mock.Mocker() as request_mocker:
        request_mocker.post(f"{web_api_address}/login", json={"sid": "sid"})
        request_mocker.post(f"{web_api_address}/add-host", json={})
        request_mocker.post(f"{web_api_address}/logout", json={})

        main()


def get_treat_protection_response():
    with open("./test_data/threat_protection_response.json", encoding="utf-8") as f:
        return json.loads(f.read())


def test_checkpoint_show_threat_protection(mocker):
    response = get_treat_protection_response()
    mocked_client = mocker.Mock()
    mocked_client.show_threat_protection.return_value = response
    results = CheckPointFirewallV2.checkpoint_show_threat_protection_command(mocked_client, {})
    assert "41e821a0-3720-11e3-aa6e-0800200c9fde" in results.readable_output
    assert "CheckPoint data for show threat protection" in results.readable_output


def test_ip_settings():
    keys = [
        "exclude-protection-with-performance-impact",
        "exclude-protection-with-performance-impact-mode",
        "exclude-protection-with-severity",
        "exclude-protection-with-severity-mode",
        "newly-updated-protections",
    ]
    for item in keys:
        assert CheckPointFirewallV2.ip_settings({item: ""}).get("ips-settings", {}).get(item) == ""


def test_checkpoint_add_threat_profile(mocker):
    response = get_treat_protection_response()
    mocked_client = mocker.Mock()
    mocked_client.add_threat_profile.return_value = response
    results = CheckPointFirewallV2.checkpoint_add_threat_profile_command(mocked_client, {})
    assert "41e821a0-3720-11e3-aa6e-0800200c9fde" in results.readable_output
    assert "CheckPoint data for add threat profile command" in results.readable_output


def test_checkpoint_delete_threat_protections(mocker):
    response = get_treat_protection_response()
    mocked_client = mocker.Mock()
    mocked_client.delete_threat_protections.return_value = response
    results = CheckPointFirewallV2.checkpoint_delete_threat_protections_command(mocked_client, {})
    assert "41e821a0-3720-11e3-aa6e-0800200c9fde" in results.readable_output
    assert "CheckPoint data for delete threat protections" in results.readable_output


def test_checkpoint_set_threat_protections(mocker):
    response = get_treat_protection_response()
    mocked_client = mocker.Mock()
    mocked_client.set_threat_protection.return_value = response
    results = CheckPointFirewallV2.checkpoint_set_threat_protections_command(mocked_client, {})
    assert "41e821a0-3720-11e3-aa6e-0800200c9fde" in results.readable_output
    assert "heckPoint data for set threat protection" in results.readable_output


def test_create_override_data():
    args = {"profiles": "profile1, profile2", "action": "action1", "track": "track1", "capturePackets": "capturePackets1"}
    results = CheckPointFirewallV2.create_override_data(args)
    assert results["overrides"] == [
        {"profile": "profile1", "action": "action1", "track": "track1", "capture-packets": None},
        {"profile": " profile2", "action": "action1", "track": "track1", "capture-packets": None},
    ]


# =====================================================================
# Tests for new helper functions and enhanced command arguments
# =====================================================================


def test_build_nat_settings_returns_none_when_no_args():
    result = CheckPointFirewallV2.build_nat_settings()
    assert result is None


def test_build_nat_settings_returns_none_when_all_none():
    result = CheckPointFirewallV2.build_nat_settings(None, None, None, None, None)
    assert result is None


def test_build_nat_settings_auto_rule_only():
    result = CheckPointFirewallV2.build_nat_settings(nat_auto_rule="true")
    assert result == {"auto-rule": True}


def test_build_nat_settings_all_fields():
    result = CheckPointFirewallV2.build_nat_settings(
        nat_auto_rule="true",
        nat_method="hide",
        nat_ip="10.0.0.1",
        nat_install_on="GW1",
        nat_hide_behind="ip_address",
    )
    assert result == {
        "auto-rule": True,
        "method": "hide",
        "ipv4-address": "10.0.0.1",
        "install-on": "GW1",
        "hide-behind": "ip_address",
    }


def test_build_nat_settings_static_method():
    result = CheckPointFirewallV2.build_nat_settings(
        nat_auto_rule="true",
        nat_method="static",
        nat_ip="192.168.1.100",
    )
    assert result == {
        "auto-rule": True,
        "method": "static",
        "ipv4-address": "192.168.1.100",
    }


def test_build_nat_settings_auto_rule_false():
    result = CheckPointFirewallV2.build_nat_settings(nat_auto_rule="false")
    assert result == {"auto-rule": False}


def test_build_interfaces_list_returns_none_when_no_args():
    result = CheckPointFirewallV2.build_interfaces_list()
    assert result is None


def test_build_interfaces_list_returns_none_when_all_none():
    result = CheckPointFirewallV2.build_interfaces_list(None, None, None)
    assert result is None


def test_build_interfaces_list_name_only():
    """When only interfaces_name is provided, should raise ValueError since all interface args are required."""
    import pytest

    with pytest.raises(ValueError, match="all interface arguments are required"):
        CheckPointFirewallV2.build_interfaces_list(interfaces_name="eth0")


def test_build_interfaces_list_all_fields():
    result = CheckPointFirewallV2.build_interfaces_list(
        interfaces_name="eth0",
        interfaces_subnet="10.0.0.0",
        interfaces_mask_length="24",
    )
    assert result == [{"name": "eth0", "subnet4": "10.0.0.0", "mask-length4": 24}]


def test_build_interfaces_list_subnet_only():
    """When only interfaces_subnet is provided, should raise ValueError since all interface args are required."""
    import pytest

    with pytest.raises(ValueError, match="all interface arguments are required"):
        CheckPointFirewallV2.build_interfaces_list(interfaces_subnet="192.168.1.0")


def test_add_host_with_nat_settings(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response

    checkpoint_add_host_command(
        mocked_client,
        "host1",
        "1.2.3.4",
        nat_auto_rule="true",
        nat_method="hide",
        nat_install_on="GW1",
        nat_hide_behind="gateway",
    )

    call_kwargs = mocked_client.add_host.call_args
    assert call_kwargs[1]["nat_settings"] == {
        "auto-rule": True,
        "method": "hide",
        "install-on": "GW1",
        "hide-behind": "gateway",
    }


def test_add_host_with_interfaces(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response

    checkpoint_add_host_command(
        mocked_client,
        "host1",
        "1.2.3.4",
        interfaces_name="eth0",
        interfaces_subnet="10.0.0.0",
        interfaces_mask_length="24",
    )

    call_kwargs = mocked_client.add_host.call_args
    assert call_kwargs[1]["interfaces"] == [{"name": "eth0", "subnet4": "10.0.0.0", "mask-length4": 24}]


def test_add_host_with_color_and_tags(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response

    checkpoint_add_host_command(
        mocked_client,
        "host1",
        "1.2.3.4",
        color="red",
        tags="tag1,tag2",
        comments="test comment",
    )

    call_kwargs = mocked_client.add_host.call_args
    assert call_kwargs[1]["color"] == "red"
    assert call_kwargs[1]["tags"] == ["tag1", "tag2"]
    assert call_kwargs[1]["comments"] == "test comment"


def test_add_host_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response

    checkpoint_add_host_command(mocked_client, "host1", "1.2.3.4", False, False)

    call_kwargs = mocked_client.add_host.call_args
    assert call_kwargs[1]["nat_settings"] is None
    assert call_kwargs[1]["interfaces"] is None
    assert call_kwargs[1]["tags"] is None


def test_update_host_with_nat_settings(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response

    checkpoint_update_host_command(
        mocked_client,
        "host1",
        nat_auto_rule="true",
        nat_method="static",
        nat_ip="192.168.1.100",
    )

    call_kwargs = mocked_client.update_host.call_args
    assert call_kwargs[1]["nat_settings"] == {
        "auto-rule": True,
        "method": "static",
        "ipv4-address": "192.168.1.100",
    }


def test_update_host_with_interfaces(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response

    checkpoint_update_host_command(
        mocked_client,
        "host1",
        interfaces_name="eth1",
        interfaces_subnet="172.16.0.0",
        interfaces_mask_length="16",
    )

    call_kwargs = mocked_client.update_host.call_args
    assert call_kwargs[1]["interfaces"] == [{"name": "eth1", "subnet4": "172.16.0.0", "mask-length4": 16}]


def test_update_host_with_color_tags_comments(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response

    checkpoint_update_host_command(
        mocked_client,
        "host1",
        color="blue",
        tags="tagA,tagB",
        comments="updated comment",
        new_name="host1_renamed",
        ip_address="5.5.5.5",
    )

    call_kwargs = mocked_client.update_host.call_args
    assert call_kwargs[1]["color"] == "blue"
    assert call_kwargs[1]["tags"] == ["tagA", "tagB"]
    assert call_kwargs[1]["comments"] == "updated comment"
    assert call_kwargs[1]["new_name"] == "host1_renamed"
    assert call_kwargs[1]["ip_address"] == "5.5.5.5"


def test_update_host_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response

    checkpoint_update_host_command(mocked_client, "host1", False, False)

    call_kwargs = mocked_client.update_host.call_args
    assert call_kwargs[1]["nat_settings"] is None
    assert call_kwargs[1]["interfaces"] is None
    assert call_kwargs[1]["tags"] is None


def test_list_hosts_with_details_level(mocker):
    from CheckPointFirewallV2 import checkpoint_list_hosts_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_host_response.json")
    mocked_client.list_hosts.return_value = mock_response

    checkpoint_list_hosts_command(mocked_client, 50, 0, details_level="full")

    call_args = mocked_client.list_hosts.call_args
    assert call_args[0] == (50, 0)
    assert call_args[1]["details_level"] == "full"


def test_list_hosts_with_domains_to_process(mocker):
    from CheckPointFirewallV2 import checkpoint_list_hosts_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_host_response.json")
    mocked_client.list_hosts.return_value = mock_response

    checkpoint_list_hosts_command(mocked_client, 50, 0, domains_to_process="domain1,domain2")

    call_args = mocked_client.list_hosts.call_args
    assert call_args[1]["domains_to_process"] == ["domain1", "domain2"]


def test_list_hosts_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_hosts_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_host_response.json")
    mocked_client.list_hosts.return_value = mock_response

    checkpoint_list_hosts_command(mocked_client, 50, 0)

    call_args = mocked_client.list_hosts.call_args
    assert call_args[1]["details_level"] is None
    assert call_args[1]["domains_to_process"] is None


def test_get_host_with_details_level(mocker):
    from CheckPointFirewallV2 import checkpoint_get_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_host_response.json")
    mocked_client.get_host.return_value = mock_response

    checkpoint_get_host_command(mocked_client, "host1", details_level="full")

    call_args = mocked_client.get_host.call_args
    assert call_args[0] == ("host1",)
    assert call_args[1]["details_level"] == "full"


def test_get_host_without_details_level(mocker):
    from CheckPointFirewallV2 import checkpoint_get_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_host_response.json")
    mocked_client.get_host.return_value = mock_response

    checkpoint_get_host_command(mocked_client, "host1")

    call_args = mocked_client.get_host.call_args
    assert call_args[1]["details_level"] is None


def test_add_group_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_group.json")
    mocked_client.add_group.return_value = mock_response

    checkpoint_add_group_command(
        mocked_client,
        "group1",
        members="member1,member2",
        comments="group comment",
        color="green",
        tags="tag1,tag2",
        ignore_warnings="true",
        ignore_errors="false",
    )

    call_kwargs = mocked_client.add_group.call_args
    assert call_kwargs[1]["members"] == ["member1", "member2"]
    assert call_kwargs[1]["comments"] == "group comment"
    assert call_kwargs[1]["color"] == "green"
    assert call_kwargs[1]["tags"] == ["tag1", "tag2"]
    assert call_kwargs[1]["ignore_warnings"] is True
    assert call_kwargs[1]["ignore_errors"] is False


def test_add_group_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_group.json")
    mocked_client.add_group.return_value = mock_response

    checkpoint_add_group_command(mocked_client, "group1")

    call_kwargs = mocked_client.add_group.call_args
    assert call_kwargs[1]["members"] is None
    assert call_kwargs[1]["tags"] is None


def test_update_group_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_group.json")
    mocked_client.update_group.return_value = mock_response

    checkpoint_update_group_command(
        mocked_client,
        "group1",
        new_name="group1_renamed",
        comments="updated",
        color="red",
        tags="tagX",
        details_level="full",
    )

    call_kwargs = mocked_client.update_group.call_args
    assert call_kwargs[1]["new_name"] == "group1_renamed"
    assert call_kwargs[1]["comments"] == "updated"
    assert call_kwargs[1]["color"] == "red"
    assert call_kwargs[1]["tags"] == ["tagX"]
    assert call_kwargs[1]["details_level"] == "full"


def test_update_group_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_group.json")
    mocked_client.update_group.return_value = mock_response

    checkpoint_update_group_command(mocked_client, "group1", False, False)

    call_kwargs = mocked_client.update_group.call_args
    assert call_kwargs[1]["new_name"] is None
    assert call_kwargs[1]["tags"] is None


def test_list_groups_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_groups_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_groups.json")
    mocked_client.list_groups.return_value = mock_response

    checkpoint_list_groups_command(
        mocked_client,
        10,
        0,
        details_level="full",
        domains_to_process="dom1,dom2",
        filter="test_filter",
    )

    call_args = mocked_client.list_groups.call_args
    assert call_args[0] == (10, 0)
    assert call_args[1]["details_level"] == "full"
    assert call_args[1]["domains_to_process"] == ["dom1", "dom2"]
    assert call_args[1]["filter_exp"] == "test_filter"


def test_list_groups_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_groups_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_groups.json")
    mocked_client.list_groups.return_value = mock_response

    checkpoint_list_groups_command(mocked_client, 10, 0)

    call_args = mocked_client.list_groups.call_args
    assert call_args[1]["details_level"] is None
    assert call_args[1]["domains_to_process"] is None
    assert call_args[1]["filter_exp"] is None


def test_get_group_with_details_level(mocker):
    from CheckPointFirewallV2 import checkpoint_get_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_group.json")
    mocked_client.get_group.return_value = mock_response

    checkpoint_get_group_command(mocked_client, "group1", details_level="full")

    call_args = mocked_client.get_group.call_args
    assert call_args[0] == ("group1",)
    assert call_args[1]["details_level"] == "full"


def test_get_group_without_details_level(mocker):
    from CheckPointFirewallV2 import checkpoint_get_group_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_group.json")
    mocked_client.get_group.return_value = mock_response

    checkpoint_get_group_command(mocked_client, "group1")

    call_args = mocked_client.get_group.call_args
    assert call_args[1]["details_level"] is None


def test_add_address_range_with_nat_and_color(mocker):
    from CheckPointFirewallV2 import checkpoint_add_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_address_range.json")
    mocked_client.add_address_range.return_value = mock_response

    checkpoint_add_address_range_command(
        mocked_client,
        "range1",
        "10.0.0.1",
        "10.0.0.100",
        color="blue",
        tags="tag1,tag2",
        comments="range comment",
        nat_auto_rule="true",
        nat_method="hide",
        nat_install_on="GW1",
        nat_hide_behind="gateway",
    )

    call_kwargs = mocked_client.add_address_range.call_args
    assert call_kwargs[1]["color"] == "blue"
    assert call_kwargs[1]["tags"] == ["tag1", "tag2"]
    assert call_kwargs[1]["comments"] == "range comment"
    assert call_kwargs[1]["nat_settings"] == {
        "auto-rule": True,
        "method": "hide",
        "install-on": "GW1",
        "hide-behind": "gateway",
    }


def test_add_address_range_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_address_range.json")
    mocked_client.add_address_range.return_value = mock_response

    checkpoint_add_address_range_command(
        mocked_client,
        "range1",
        "10.0.0.1",
        "10.0.0.100",
        False,
        False,
        False,
    )

    call_kwargs = mocked_client.add_address_range.call_args
    assert call_kwargs[1]["nat_settings"] is None
    assert call_kwargs[1]["tags"] is None


def test_update_address_range_with_nat_and_color(mocker):
    from CheckPointFirewallV2 import checkpoint_update_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_address_range.json")
    mocked_client.update_address_range.return_value = mock_response

    checkpoint_update_address_range_command(
        mocked_client,
        "range1",
        color="red",
        tags="tagA",
        nat_method="static",
        nat_ip="10.10.10.10",
    )

    call_kwargs = mocked_client.update_address_range.call_args
    assert call_kwargs[1]["color"] == "red"
    assert call_kwargs[1]["tags"] == ["tagA"]
    assert call_kwargs[1]["nat_settings"] == {
        "method": "static",
        "ipv4-address": "10.10.10.10",
    }


def test_update_address_range_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_address_range.json")
    mocked_client.update_address_range.return_value = mock_response

    checkpoint_update_address_range_command(mocked_client, "range1", False, False)

    call_kwargs = mocked_client.update_address_range.call_args
    assert call_kwargs[1]["nat_settings"] is None
    assert call_kwargs[1]["tags"] is None


def test_list_address_range_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_address_range.json")
    mocked_client.list_address_ranges.return_value = mock_response

    checkpoint_list_address_range_command(
        mocked_client,
        10,
        0,
        details_level="full",
        domains_to_process="dom1,dom2",
    )

    call_args = mocked_client.list_address_ranges.call_args
    assert call_args[0] == (10, 0)
    assert call_args[1]["details_level"] == "full"
    assert call_args[1]["domains_to_process"] == ["dom1", "dom2"]


def test_list_address_range_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_address_range.json")
    mocked_client.list_address_ranges.return_value = mock_response

    checkpoint_list_address_range_command(mocked_client, 10, 0)

    call_args = mocked_client.list_address_ranges.call_args
    assert call_args[1]["details_level"] is None
    assert call_args[1]["domains_to_process"] is None


def test_add_threat_indicator_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_threat_indicator.json")
    mocked_client.add_threat_indicator.return_value = mock_response

    checkpoint_add_threat_indicator_command(
        mocked_client,
        "indicator1",
        profile_action="Standard Threat Prevention_prevent,Strict Threat Prevention_detect",
        comments="indicator comment",
        color="yellow",
        tags="tag1,tag2",
        action="Prevent",
        ignore_warnings="true",
    )

    call_kwargs = mocked_client.add_threat_indicator.call_args
    assert call_kwargs[1]["comments"] == "indicator comment"
    assert call_kwargs[1]["color"] == "yellow"
    assert call_kwargs[1]["tags"] == ["tag1", "tag2"]
    assert call_kwargs[1]["action"] == "Prevent"
    assert call_kwargs[1]["profile_overrides"] == [
        {"profile": "Standard Threat Prevention", "action": "prevent"},
        {"profile": "Strict Threat Prevention", "action": "detect"},
    ]
    assert call_kwargs[1]["ignore_warnings"] is True


def test_add_threat_indicator_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_threat_indicator.json")
    mocked_client.add_threat_indicator.return_value = mock_response

    checkpoint_add_threat_indicator_command(mocked_client, "indicator1", profile_action="Minimal_inactive", observables=[])

    call_kwargs = mocked_client.add_threat_indicator.call_args
    assert call_kwargs[1]["tags"] is None
    assert call_kwargs[1]["profile_overrides"] == [{"profile": "Minimal", "action": "inactive"}]


def test_update_threat_indicator_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_threat_indicator.json")
    mocked_client.update_threat_indicator.return_value = mock_response

    checkpoint_update_threat_indicator_command(
        mocked_client,
        "indicator1",
        profile_action="Standard Threat Prevention_prevent,Strict Threat Prevention_detect",
        color="orange",
        tags="tagZ",
    )

    call_kwargs = mocked_client.update_threat_indicator.call_args
    assert call_kwargs[1]["profile_overrides"] == [
        {"profile": "Standard Threat Prevention", "action": "prevent"},
        {"profile": "Strict Threat Prevention", "action": "detect"},
    ]
    assert call_kwargs[1]["color"] == "orange"
    assert call_kwargs[1]["tags"] == ["tagZ"]


def test_update_threat_indicator_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_threat_indicator.json")
    mocked_client.update_threat_indicator.return_value = mock_response

    checkpoint_update_threat_indicator_command(mocked_client, "indicator1", profile_action="Minimal_inactive")

    call_kwargs = mocked_client.update_threat_indicator.call_args
    assert call_kwargs[1]["profile_overrides"] == [{"profile": "Minimal", "action": "inactive"}]
    assert call_kwargs[1]["tags"] is None


def test_list_threat_indicator_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_threat_indicator.json")
    mocked_client.list_threat_indicators.return_value = mock_response

    checkpoint_list_threat_indicator_command(
        mocked_client,
        10,
        0,
        domain_names="dom1,dom2",
        details_level="full",
        filter="test_filter",
    )

    call_args = mocked_client.list_threat_indicators.call_args
    assert call_args[0] == (10, 0)
    assert call_args[1]["domain_names"] == ["dom1", "dom2"]
    assert call_args[1]["details_level"] == "full"
    assert call_args[1]["filter_exp"] == "test_filter"


def test_list_threat_indicator_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_threat_indicator_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_threat_indicator.json")
    mocked_client.list_threat_indicators.return_value = mock_response

    checkpoint_list_threat_indicator_command(mocked_client, 10, 0)

    call_args = mocked_client.list_threat_indicators.call_args
    assert call_args[1]["domain_names"] is None
    assert call_args[1]["details_level"] is None
    assert call_args[1]["filter_exp"] is None


def test_add_access_rule_with_track_and_install_on(mocker):
    from CheckPointFirewallV2 import checkpoint_add_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_rule.json")
    mocked_client.add_rule.return_value = mock_response

    checkpoint_add_access_rule_command(
        mocked_client,
        "Network",
        "top",
        comments="rule comment",
        install_on="GW1,GW2",
        enabled="true",
        track_type="Log",
        track_accounting="true",
        track_per_session="false",
    )

    call_kwargs = mocked_client.add_rule.call_args
    assert call_kwargs[1]["comments"] == "rule comment"
    assert call_kwargs[1]["install_on"] == ["GW1", "GW2"]
    assert call_kwargs[1]["enabled"] is True
    assert call_kwargs[1]["track"] == {
        "type": "Log",
        "accounting": True,
        "per-session": False,
    }


def test_add_access_rule_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_rule.json")
    mocked_client.add_rule.return_value = mock_response

    checkpoint_add_access_rule_command(mocked_client, "Network", "top")

    call_kwargs = mocked_client.add_rule.call_args
    assert call_kwargs[1]["install_on"] is None
    assert call_kwargs[1]["enabled"] is None
    assert call_kwargs[1]["track"] is None


def test_update_access_rule_with_track_and_incremental(mocker):
    from CheckPointFirewallV2 import checkpoint_update_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_rule.json")
    mocked_client.update_rule.return_value = mock_response

    checkpoint_update_access_rule_command(
        mocked_client,
        "rule1",
        "Network",
        comments="updated rule",
        track_type="Extended Log",
        track_accounting="false",
        track_per_session="true",
        install_on="GW1",
        source_add="src1,src2",
        source_remove="src3",
        destination_add="dst1",
        destination_remove="dst2",
        service_add="svc1",
        service_remove="svc2",
    )

    call_kwargs = mocked_client.update_rule.call_args
    assert call_kwargs[1]["comments"] == "updated rule"
    assert call_kwargs[1]["track"] == {
        "type": "Extended Log",
        "accounting": False,
        "per-session": True,
    }
    assert call_kwargs[1]["install_on"] == ["GW1"]
    assert call_kwargs[1]["source"] == {"add": ["src1", "src2"], "remove": ["src3"]}
    assert call_kwargs[1]["destination"] == {"add": ["dst1"], "remove": ["dst2"]}
    assert call_kwargs[1]["service"] == {"add": ["svc1"], "remove": ["svc2"]}


def test_update_access_rule_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_rule.json")
    mocked_client.update_rule.return_value = mock_response

    checkpoint_update_access_rule_command(mocked_client, "rule1", "Network", False, False)

    call_kwargs = mocked_client.update_rule.call_args
    assert call_kwargs[1]["track"] is None
    assert call_kwargs[1]["install_on"] is None
    assert call_kwargs[1]["source"] is None
    assert call_kwargs[1]["destination"] is None
    assert call_kwargs[1]["service"] is None


def test_list_access_rule_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_access_rule.json")
    mocked_client.list_access_rule.return_value = mock_response

    checkpoint_list_access_rule_command(
        mocked_client,
        "Network",
        10,
        0,
        details_level="full",
        show_hits="true",
    )

    call_args = mocked_client.list_access_rule.call_args
    assert call_args[0] == ("Network", 10, 0)
    assert call_args[1]["details_level"] == "full"
    assert call_args[1]["show_hits"] is True


def test_list_access_rule_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_access_rule_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_access_rule.json")
    mocked_client.list_access_rule.return_value = mock_response

    checkpoint_list_access_rule_command(mocked_client, "Network", 10, 0)

    call_args = mocked_client.list_access_rule.call_args
    assert call_args[1]["details_level"] is None
    assert call_args[1]["show_hits"] is None


def test_add_application_site_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_application_site.json")
    mocked_client.add_application_site.return_value = mock_response

    checkpoint_add_application_site_command(
        mocked_client,
        "app1",
        "TestCat",
        "example.com",
        description="test desc",
        comments="app comment",
        color="cyan",
        tags="tag1,tag2",
    )

    call_kwargs = mocked_client.add_application_site.call_args
    assert call_kwargs[1]["description"] == "test desc"
    assert call_kwargs[1]["comments"] == "app comment"
    assert call_kwargs[1]["color"] == "cyan"
    assert call_kwargs[1]["tags"] == ["tag1", "tag2"]


def test_add_application_site_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_add_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_application_site.json")
    mocked_client.add_application_site.return_value = mock_response

    checkpoint_add_application_site_command(mocked_client, "app1", "TestCat", "example.com")

    call_kwargs = mocked_client.add_application_site.call_args
    assert call_kwargs[1]["tags"] is None
    assert call_kwargs[1]["comments"] is None


def test_update_application_site_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_application_site.json")
    mocked_client.update_application_site.return_value = mock_response

    checkpoint_update_application_site_command(
        mocked_client,
        "app1",
        False,
        comments="updated app",
        color="magenta",
        tags="tagM",
    )

    call_kwargs = mocked_client.update_application_site.call_args
    assert call_kwargs[1]["comments"] == "updated app"
    assert call_kwargs[1]["color"] == "magenta"
    assert call_kwargs[1]["tags"] == ["tagM"]


def test_update_application_site_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_update_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_application_site.json")
    mocked_client.update_application_site.return_value = mock_response

    checkpoint_update_application_site_command(mocked_client, "app1", False)

    call_kwargs = mocked_client.update_application_site.call_args
    assert call_kwargs[1]["tags"] is None
    assert call_kwargs[1]["comments"] is None


def test_list_application_site_with_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_application_site.json")
    mocked_client.list_application_site.return_value = mock_response

    checkpoint_list_application_site_command(
        mocked_client,
        10,
        0,
        details_level="full",
        domains_to_process="dom1,dom2",
    )

    call_args = mocked_client.list_application_site.call_args
    assert call_args[0] == (10, 0)
    assert call_args[1]["details_level"] == "full"
    assert call_args[1]["domains_to_process"] == ["dom1", "dom2"]


def test_list_application_site_without_new_args(mocker):
    from CheckPointFirewallV2 import checkpoint_list_application_site_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_application_site.json")
    mocked_client.list_application_site.return_value = mock_response

    checkpoint_list_application_site_command(mocked_client, 10, 0)

    call_args = mocked_client.list_application_site.call_args
    assert call_args[1]["details_level"] is None
    assert call_args[1]["domains_to_process"] is None

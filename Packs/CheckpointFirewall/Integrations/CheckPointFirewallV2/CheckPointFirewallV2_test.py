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
    assert len(result[0]) == 12


def test_checkpoint_get_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_get_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_host_response.json")
    mocked_client.get_host.return_value = mock_response
    result = checkpoint_get_host_command(mocked_client, "host 1").outputs
    assert result.get("name") == "host 1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "host"
    assert len(result) == 17


def test_checkpoint_add_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_add_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_host_response.json")
    mocked_client.add_host.return_value = mock_response
    result = checkpoint_add_host_command(mocked_client, "host 1", "1.2.3.4", False, False).outputs
    assert result[0].get("name") == "add host"
    assert result[0].get("uid") == "123"
    assert result[0].get("type") == "host"
    assert len(result[0]) == 20


def test_checkpoint_update_host_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_host_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_host_response.json")
    mocked_client.update_host.return_value = mock_response
    result = checkpoint_update_host_command(mocked_client, "host 1", False, False).outputs
    assert result.get("name") == "update host"
    assert result.get("uid") == "123"
    assert result.get("type") == "host"
    assert len(result) == 13


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
    assert len(result[0]) == 12


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
    assert len(result) == 12


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
    assert len(result[0]) == 12


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
    assert len(result[0]) == 12


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
    assert len(result) == 21


def test_checkpoint_update_address_range_command(mocker):
    from CheckPointFirewallV2 import checkpoint_update_address_range_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_address_range.json")
    mocked_client.update_address_range.return_value = mock_response
    result = checkpoint_update_address_range_command(mocked_client, "address_range_1", False, False).outputs
    assert result.get("name") == "address_range_1"
    assert result.get("uid") == "1234"
    assert result.get("type") == "address-range"
    assert len(result) == 18


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
    assert len(result[2]) == 12


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
    assert len(result) == 14


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
    assert len(result[0]) == 12


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


# ==================== Service Group Commands ====================


def test_checkpoint_service_group_add_command(mocker):
    """
    Given
        a client and service group parameters
    When
        calling checkpoint_service_group_add_command
    Then
        validate the result contains the expected service group data
    """
    from CheckPointFirewallV2 import checkpoint_service_group_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_service_group.json")
    mocked_client.add_service_group.return_value = mock_response

    result = checkpoint_service_group_add_command(mocked_client, name="test-service-group", members="http")
    assert result.outputs.get("name") == "test-service-group"
    assert result.outputs.get("uid") == "sg-1234"
    assert result.outputs.get("type") == "service-group"
    mocked_client.add_service_group.assert_called_once_with(
        name="test-service-group",
        members=["http"],
        color=None,
        comments=None,
        details_level=None,
        groups=None,
        tags=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_service_group_add_command_with_optional_args(mocker):
    """
    Given
        a client and service group parameters including optional args
    When
        calling checkpoint_service_group_add_command with color, comments, ignore_warnings
    Then
        validate the client method is called with the correct parsed arguments
    """
    from CheckPointFirewallV2 import checkpoint_service_group_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_service_group.json")
    mocked_client.add_service_group.return_value = mock_response

    result = checkpoint_service_group_add_command(
        mocked_client,
        name="test-service-group",
        members="http,https",
        color="blue",
        comments="test comment",
        ignore_warnings="true",
        ignore_errors="false",
        tags="tag1,tag2",
        groups="group1",
    )
    assert result.outputs.get("name") == "test-service-group"
    mocked_client.add_service_group.assert_called_once_with(
        name="test-service-group",
        members=["http", "https"],
        color="blue",
        comments="test comment",
        details_level=None,
        groups=["group1"],
        tags=["tag1", "tag2"],
        ignore_warnings=True,
        ignore_errors=False,
    )


def test_checkpoint_service_group_get_command(mocker):
    """
    Given
        a client and a service group identifier
    When
        calling checkpoint_service_group_get_command
    Then
        validate the result contains the expected service group data with members
    """
    from CheckPointFirewallV2 import checkpoint_service_group_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_service_group.json")
    mocked_client.get_service_group.return_value = mock_response

    result = checkpoint_service_group_get_command(mocked_client, identifier="test-service-group")
    assert result.outputs.get("name") == "test-service-group"
    assert result.outputs.get("uid") == "sg-1234"
    assert result.outputs.get("type") == "service-group"
    assert len(result.outputs.get("members")) == 2
    mocked_client.get_service_group.assert_called_once_with(
        identifier="test-service-group",
        show_as_ranges=None,
        details_level=None,
    )


def test_checkpoint_service_group_get_command_with_show_as_ranges(mocker):
    """
    Given
        a client and a service group identifier with show_as_ranges=true
    When
        calling checkpoint_service_group_get_command
    Then
        validate show_as_ranges is parsed as boolean
    """
    from CheckPointFirewallV2 import checkpoint_service_group_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_service_group.json")
    mocked_client.get_service_group.return_value = mock_response

    checkpoint_service_group_get_command(
        mocked_client, identifier="test-service-group", show_as_ranges="true", details_level="full"
    )
    mocked_client.get_service_group.assert_called_once_with(
        identifier="test-service-group",
        show_as_ranges=True,
        details_level="full",
    )


def test_checkpoint_service_group_list_command(mocker):
    """
    Given
        a client
    When
        calling checkpoint_service_group_list_command
    Then
        validate the result contains the expected list of service groups
    """
    from CheckPointFirewallV2 import checkpoint_service_group_list_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_service_groups.json")
    mocked_client.list_service_groups.return_value = mock_response

    result = checkpoint_service_group_list_command(mocked_client)
    assert len(result.outputs) == 2
    assert result.outputs[0].get("name") == "service-group-1"
    assert result.outputs[0].get("uid") == "sg-1234"
    assert result.outputs[1].get("name") == "service-group-2"


def test_checkpoint_service_group_list_command_empty(mocker):
    """
    Given
        a client
    When
        calling checkpoint_service_group_list_command with no results
    Then
        validate the readable output indicates no results
    """
    from CheckPointFirewallV2 import checkpoint_service_group_list_command

    mocked_client = mocker.Mock()
    mocked_client.list_service_groups.return_value = {"objects": []}

    result = checkpoint_service_group_list_command(mocked_client)
    assert result.readable_output == "No service group objects were found."


def test_checkpoint_service_group_list_command_domains_to_process_with_full_details(mocker):
    """
    Given
        a client with domains_to_process and details_level=full
    When
        calling checkpoint_service_group_list_command
    Then
        validate a DemistoException is raised
    """
    from CheckPointFirewallV2 import checkpoint_service_group_list_command

    mocked_client = mocker.Mock()

    with pytest.raises(CheckPointFirewallV2.DemistoException, match="cannot be used with details_level set to 'full'"):
        checkpoint_service_group_list_command(mocked_client, domains_to_process="CURRENT_DOMAIN", details_level="full")


def test_checkpoint_service_group_update_command(mocker):
    """
    Given
        a client and update parameters
    When
        calling checkpoint_service_group_update_command
    Then
        validate the result contains the updated service group data
    """
    from CheckPointFirewallV2 import checkpoint_service_group_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_service_group.json")
    mocked_client.update_service_group.return_value = mock_response

    result = checkpoint_service_group_update_command(
        mocked_client, identifier="test-service-group", new_name="updated-service-group"
    )
    assert result.outputs.get("name") == "updated-service-group"
    assert result.outputs.get("uid") == "sg-1234"
    mocked_client.update_service_group.assert_called_once_with(
        identifier="test-service-group",
        members=None,
        new_name="updated-service-group",
        color=None,
        comments=None,
        ignore_warnings=None,
        ignore_errors=None,
        details_level=None,
        groups=None,
        tags=None,
    )


def test_checkpoint_service_group_update_command_with_members_action(mocker):
    """
    Given
        a client and update parameters with members_action=add
    When
        calling checkpoint_service_group_update_command
    Then
        validate members are wrapped with the action key
    """
    from CheckPointFirewallV2 import checkpoint_service_group_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_service_group.json")
    mocked_client.update_service_group.return_value = mock_response

    checkpoint_service_group_update_command(
        mocked_client,
        identifier="test-service-group",
        members_action="add",
        members="http,https",
        groups_action="remove",
        groups="old-group",
        tags_action="add",
        tags="new-tag",
    )
    mocked_client.update_service_group.assert_called_once_with(
        identifier="test-service-group",
        members={"add": ["http", "https"]},
        new_name=None,
        color=None,
        comments=None,
        ignore_warnings=None,
        ignore_errors=None,
        details_level=None,
        groups={"remove": ["old-group"]},
        tags={"add": ["new-tag"]},
    )


def test_checkpoint_service_group_update_command_members_without_action(mocker):
    """
    Given
        a client and update parameters with members but no members_action
    When
        calling checkpoint_service_group_update_command
    Then
        validate members are passed as a plain list (no action wrapping)
    """
    from CheckPointFirewallV2 import checkpoint_service_group_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_service_group.json")
    mocked_client.update_service_group.return_value = mock_response

    checkpoint_service_group_update_command(
        mocked_client,
        identifier="test-service-group",
        members="http,https",
    )
    mocked_client.update_service_group.assert_called_once_with(
        identifier="test-service-group",
        members=["http", "https"],
        new_name=None,
        color=None,
        comments=None,
        ignore_warnings=None,
        ignore_errors=None,
        details_level=None,
        groups=None,
        tags=None,
    )


def test_checkpoint_service_group_clone_command(mocker):
    """
    Given
        a client and clone parameters
    When
        calling checkpoint_service_group_clone_command
    Then
        validate the result contains the cloned service group data
    """
    from CheckPointFirewallV2 import checkpoint_service_group_clone_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/clone_service_group.json")
    mocked_client.clone_service_group.return_value = mock_response

    result = checkpoint_service_group_clone_command(
        mocked_client, identifier="test-service-group", new_name="cloned-service-group"
    )
    assert result.outputs.get("name") == "cloned-service-group"
    assert result.outputs.get("uid") == "sg-9999"
    assert result.outputs.get("type") == "service-group"


def test_checkpoint_service_group_clone_command_with_action(mocker):
    """
    Given
        a client and clone parameters with members_action
    When
        calling checkpoint_service_group_clone_command
    Then
        validate members are wrapped with the action key
    """
    from CheckPointFirewallV2 import checkpoint_service_group_clone_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/clone_service_group.json")
    mocked_client.clone_service_group.return_value = mock_response

    checkpoint_service_group_clone_command(
        mocked_client,
        identifier="test-service-group",
        members_action="add",
        members="ftp",
    )
    mocked_client.clone_service_group.assert_called_once_with(
        identifier="test-service-group",
        members={"add": ["ftp"]},
        new_name=None,
        color=None,
        comments=None,
        ignore_warnings=None,
        ignore_errors=None,
        details_level=None,
        groups=None,
        tags=None,
    )


def test_checkpoint_service_group_delete_command(mocker):
    """
    Given
        a client and a service group identifier
    When
        calling checkpoint_service_group_delete_command
    Then
        validate the result indicates successful deletion
    """
    from CheckPointFirewallV2 import checkpoint_service_group_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_service_group.return_value = {"message": "OK"}

    result = checkpoint_service_group_delete_command(mocked_client, identifier="test-service-group")
    assert result.readable_output == "Service group deleted successfully"
    mocked_client.delete_service_group.assert_called_once_with(
        identifier="test-service-group",
        details_level=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_service_group_delete_command_with_optional_args(mocker):
    """
    Given
        a client and a service group identifier with optional args
    When
        calling checkpoint_service_group_delete_command
    Then
        validate optional args are parsed correctly
    """
    from CheckPointFirewallV2 import checkpoint_service_group_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_service_group.return_value = {"message": "OK"}

    checkpoint_service_group_delete_command(
        mocked_client,
        identifier="test-service-group",
        details_level="standard",
        ignore_warnings="true",
        ignore_errors="false",
    )
    mocked_client.delete_service_group.assert_called_once_with(
        identifier="test-service-group",
        details_level="standard",
        ignore_warnings=True,
        ignore_errors=False,
    )


# ==================== Access Section Commands ====================


def test_checkpoint_access_section_add_command(mocker):
    """
    Given
        a client and access section parameters with position=top
    When
        calling checkpoint_access_section_add_command
    Then
        validate the result contains the expected access section data
    """
    from CheckPointFirewallV2 import checkpoint_access_section_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_section.json")
    mocked_client.add_access_section.return_value = mock_response

    result = checkpoint_access_section_add_command(mocked_client, layer="Network", position="top", name="test-section")
    assert result.outputs.get("name") == "test-section"
    assert result.outputs.get("uid") == "as-1234"
    assert result.outputs.get("type") == "access-section"
    mocked_client.add_access_section.assert_called_once_with(
        layer="Network",
        position="top",
        details_level=None,
        name="test-section",
        tags=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_add_command_with_position_rule(mocker):
    """
    Given
        a client and access section parameters with position=above and position_rule
    When
        calling checkpoint_access_section_add_command
    Then
        validate position is constructed as a dict {position: position_rule}
    """
    from CheckPointFirewallV2 import checkpoint_access_section_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_section.json")
    mocked_client.add_access_section.return_value = mock_response

    checkpoint_access_section_add_command(
        mocked_client, layer="Network", position="above", position_rule="rule-1", name="test-section"
    )
    mocked_client.add_access_section.assert_called_once_with(
        layer="Network",
        position={"above": "rule-1"},
        details_level=None,
        name="test-section",
        tags=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_add_command_with_integer_position(mocker):
    """
    Given
        a client and access section parameters with a numeric position
    When
        calling checkpoint_access_section_add_command
    Then
        validate position is converted to an integer
    """
    from CheckPointFirewallV2 import checkpoint_access_section_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_access_section.json")
    mocked_client.add_access_section.return_value = mock_response

    checkpoint_access_section_add_command(mocked_client, layer="Network", position="3", name="test-section")
    mocked_client.add_access_section.assert_called_once_with(
        layer="Network",
        position=3,
        details_level=None,
        name="test-section",
        tags=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_add_command_above_without_position_rule(mocker):
    """
    Given
        a client with position=above but no position_rule
    When
        calling checkpoint_access_section_add_command
    Then
        validate a DemistoException is raised
    """
    from CheckPointFirewallV2 import checkpoint_access_section_add_command

    mocked_client = mocker.Mock()

    with pytest.raises(CheckPointFirewallV2.DemistoException, match="'position_rule' argument is required"):
        checkpoint_access_section_add_command(mocked_client, layer="Network", position="above", name="test-section")


def test_checkpoint_access_section_add_command_below_without_position_rule(mocker):
    """
    Given
        a client with position=below but no position_rule
    When
        calling checkpoint_access_section_add_command
    Then
        validate a DemistoException is raised
    """
    from CheckPointFirewallV2 import checkpoint_access_section_add_command

    mocked_client = mocker.Mock()

    with pytest.raises(CheckPointFirewallV2.DemistoException, match="'position_rule' argument is required"):
        checkpoint_access_section_add_command(mocked_client, layer="Network", position="below", name="test-section")


def test_checkpoint_access_section_get_command(mocker):
    """
    Given
        a client and access section parameters
    When
        calling checkpoint_access_section_get_command
    Then
        validate the result contains the expected access section data
    """
    from CheckPointFirewallV2 import checkpoint_access_section_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_access_section.json")
    mocked_client.get_access_section.return_value = mock_response

    result = checkpoint_access_section_get_command(mocked_client, layer="Network", identifier="test-section")
    assert result.outputs.get("name") == "test-section"
    assert result.outputs.get("uid") == "as-1234"
    assert result.outputs.get("type") == "access-section"
    mocked_client.get_access_section.assert_called_once_with(
        layer="Network",
        identifier="test-section",
        details_level=None,
    )


def test_checkpoint_access_section_get_command_with_details_level(mocker):
    """
    Given
        a client and access section parameters with details_level
    When
        calling checkpoint_access_section_get_command
    Then
        validate details_level is passed through
    """
    from CheckPointFirewallV2 import checkpoint_access_section_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/get_access_section.json")
    mocked_client.get_access_section.return_value = mock_response

    checkpoint_access_section_get_command(mocked_client, layer="Network", identifier="test-section", details_level="full")
    mocked_client.get_access_section.assert_called_once_with(
        layer="Network",
        identifier="test-section",
        details_level="full",
    )


def test_checkpoint_access_section_update_command(mocker):
    """
    Given
        a client and update parameters
    When
        calling checkpoint_access_section_update_command
    Then
        validate the result contains the updated access section data
    """
    from CheckPointFirewallV2 import checkpoint_access_section_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_section.json")
    mocked_client.update_access_section.return_value = mock_response

    result = checkpoint_access_section_update_command(
        mocked_client, identifier="test-section", layer="Network", new_name="updated-section"
    )
    assert result.outputs.get("name") == "updated-section"
    assert result.outputs.get("uid") == "as-1234"
    mocked_client.update_access_section.assert_called_once_with(
        identifier="test-section",
        layer="Network",
        new_name="updated-section",
        details_level=None,
        tags=None,
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_update_command_with_tags_action(mocker):
    """
    Given
        a client and update parameters with tags_action=add
    When
        calling checkpoint_access_section_update_command
    Then
        validate tags are wrapped with the action key
    """
    from CheckPointFirewallV2 import checkpoint_access_section_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_section.json")
    mocked_client.update_access_section.return_value = mock_response

    checkpoint_access_section_update_command(
        mocked_client,
        identifier="test-section",
        layer="Network",
        tags_action="add",
        tags="tag1,tag2",
    )
    mocked_client.update_access_section.assert_called_once_with(
        identifier="test-section",
        layer="Network",
        new_name=None,
        details_level=None,
        tags={"add": ["tag1", "tag2"]},
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_update_command_tags_without_action(mocker):
    """
    Given
        a client and update parameters with tags but no tags_action
    When
        calling checkpoint_access_section_update_command
    Then
        validate tags are passed as a plain list
    """
    from CheckPointFirewallV2 import checkpoint_access_section_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_access_section.json")
    mocked_client.update_access_section.return_value = mock_response

    checkpoint_access_section_update_command(
        mocked_client,
        identifier="test-section",
        layer="Network",
        tags="tag1,tag2",
    )
    mocked_client.update_access_section.assert_called_once_with(
        identifier="test-section",
        layer="Network",
        new_name=None,
        details_level=None,
        tags=["tag1", "tag2"],
        ignore_warnings=None,
        ignore_errors=None,
    )


def test_checkpoint_access_section_delete_command(mocker):
    """
    Given
        a client and access section parameters
    When
        calling checkpoint_access_section_delete_command
    Then
        validate the result indicates successful deletion
    """
    from CheckPointFirewallV2 import checkpoint_access_section_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_access_section.return_value = {"message": "OK"}

    result = checkpoint_access_section_delete_command(mocked_client, identifier="test-section", layer="Network")
    assert result.readable_output == "Access section deleted successfully."
    mocked_client.delete_access_section.assert_called_once_with(
        identifier="test-section",
        layer="Network",
        details_level=None,
    )


def test_checkpoint_access_section_delete_command_with_details_level(mocker):
    """
    Given
        a client and access section parameters with details_level
    When
        calling checkpoint_access_section_delete_command
    Then
        validate details_level is passed through
    """
    from CheckPointFirewallV2 import checkpoint_access_section_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_access_section.return_value = {"message": "OK"}

    checkpoint_access_section_delete_command(mocked_client, identifier="test-section", layer="Network", details_level="standard")
    mocked_client.delete_access_section.assert_called_once_with(
        identifier="test-section",
        layer="Network",
        details_level="standard",
    )


# ==================== Helper Function Tests ====================


class TestParseOrderArgument:
    """Tests for the parse_order_argument helper function."""

    def test_single_order(self):
        from CheckPointFirewallV2 import parse_order_argument

        result = parse_order_argument("ASC:name")
        assert result == [{"ASC": "name"}]

    def test_multiple_orders(self):
        from CheckPointFirewallV2 import parse_order_argument

        result = parse_order_argument("ASC:type,ASC:name,DESC:uid")
        assert result == [{"ASC": "type"}, {"ASC": "name"}, {"DESC": "uid"}]

    def test_lowercase_direction_normalized(self):
        from CheckPointFirewallV2 import parse_order_argument

        result = parse_order_argument("asc:name")
        assert result == [{"ASC": "name"}]

    def test_whitespace_handling(self):
        from CheckPointFirewallV2 import parse_order_argument

        result = parse_order_argument(" ASC : name , DESC : uid ")
        assert result == [{"ASC": "name"}, {"DESC": "uid"}]

    def test_invalid_format_no_colon(self):
        from CheckPointFirewallV2 import parse_order_argument

        with pytest.raises(CheckPointFirewallV2.DemistoException, match="Invalid order format"):
            parse_order_argument("ASCname")

    def test_invalid_direction(self):
        from CheckPointFirewallV2 import parse_order_argument

        with pytest.raises(CheckPointFirewallV2.DemistoException, match="Invalid order direction"):
            parse_order_argument("INVALID:name")


# ==================== Network Commands Tests ====================


def test_checkpoint_network_get_command(mocker):
    """
    Given
        a mocked client with a show_network response
    When
        calling checkpoint_network_get_command
    Then
        validate the outputs contain the expected network data
    """
    from CheckPointFirewallV2 import checkpoint_network_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_network.json")
    mocked_client.show_network.return_value = mock_response
    result = checkpoint_network_get_command(mocked_client, "test-network")
    assert result.outputs.get("name") == "test-network"
    assert result.outputs.get("uid") == "net-uid-1234"
    assert result.outputs.get("type") == "network"
    assert result.outputs_prefix == "CheckPoint.Network"


def test_checkpoint_network_get_command_with_details_level(mocker):
    """
    Given
        a mocked client with a show_network response and details_level argument
    When
        calling checkpoint_network_get_command with details_level='full'
    Then
        validate show_network is called with the correct details_level
    """
    from CheckPointFirewallV2 import checkpoint_network_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_network.json")
    mocked_client.show_network.return_value = mock_response
    checkpoint_network_get_command(mocked_client, "test-network", details_level="full")
    mocked_client.show_network.assert_called_once_with("test-network", "full")


def test_checkpoint_network_list_command(mocker):
    """
    Given
        a mocked client with a list_networks response
    When
        calling checkpoint_network_list_command
    Then
        validate the outputs contain the expected list of networks
    """
    from CheckPointFirewallV2 import checkpoint_network_list_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_networks.json")
    mocked_client.list_networks.return_value = mock_response
    result = checkpoint_network_list_command(mocked_client, limit=50, offset=0)
    assert len(result.outputs) == 2
    assert result.outputs[0].get("name") == "test-network-1"
    assert result.outputs[1].get("name") == "test-network-2"
    assert result.outputs_prefix == "CheckPoint.Network"


def test_checkpoint_network_list_command_empty(mocker):
    """
    Given
        a mocked client with an empty list_networks response
    When
        calling checkpoint_network_list_command
    Then
        validate the readable output indicates no networks found
    """
    from CheckPointFirewallV2 import checkpoint_network_list_command

    mocked_client = mocker.Mock()
    mocked_client.list_networks.return_value = {"total": 0, "objects": []}
    result = checkpoint_network_list_command(mocked_client, limit=50, offset=0)
    assert result.readable_output == "No network objects were found."
    assert result.outputs == []


def test_checkpoint_network_add_command(mocker):
    """
    Given
        a mocked client with an add_network response
    When
        calling checkpoint_network_add_command
    Then
        validate the outputs contain the expected network data
    """
    from CheckPointFirewallV2 import checkpoint_network_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_network.json")
    mocked_client.add_network.return_value = mock_response
    result = checkpoint_network_add_command(mocked_client, identifier="new-network", subnet="172.16.0.0", mask_length="24")
    assert result.outputs.get("name") == "new-network"
    assert result.outputs.get("uid") == "net-uid-new-1234"
    assert result.outputs.get("type") == "network"
    assert result.outputs_prefix == "CheckPoint.Network"


def test_checkpoint_network_add_command_with_nat(mocker):
    """
    Given
        a mocked client with an add_network response and NAT settings
    When
        calling checkpoint_network_add_command with NAT arguments
    Then
        validate add_network is called with the correct nat_settings
    """
    from CheckPointFirewallV2 import checkpoint_network_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_network.json")
    mocked_client.add_network.return_value = mock_response
    checkpoint_network_add_command(
        mocked_client,
        identifier="new-network",
        subnet="172.16.0.0",
        mask_length="24",
        nat_settings_auto_rule="true",
        nat_method="hide",
        nat_hide_behind="gateway",
    )
    call_kwargs = mocked_client.add_network.call_args[1]
    assert call_kwargs["nat_settings"]["auto-rule"] is True
    assert call_kwargs["nat_settings"]["method"] == "hide"
    assert call_kwargs["nat_settings"]["hide-behind"] == "gateway"


def test_checkpoint_network_update_command(mocker):
    """
    Given
        a mocked client with an update_network response
    When
        calling checkpoint_network_update_command
    Then
        validate the outputs contain the expected updated network data
    """
    from CheckPointFirewallV2 import checkpoint_network_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/update_network.json")
    mocked_client.update_network.return_value = mock_response
    result = checkpoint_network_update_command(mocked_client, identifier="test-network", new_identifier="updated-network")
    assert result.outputs.get("name") == "updated-network"
    assert result.outputs.get("uid") == "net-uid-1234"
    assert result.outputs_prefix == "CheckPoint.Network"


def test_checkpoint_network_delete_command(mocker):
    """
    Given
        a mocked client
    When
        calling checkpoint_network_delete_command
    Then
        validate the readable output indicates successful deletion
    """
    from CheckPointFirewallV2 import checkpoint_network_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_network.return_value = {"message": "OK"}
    result = checkpoint_network_delete_command(mocked_client, identifier="test-network")
    assert result.readable_output == "Object deleted successfully."
    mocked_client.delete_network.assert_called_once_with("test-network", True)


def test_checkpoint_network_delete_command_ignore_warnings_false(mocker):
    """
    Given
        a mocked client with ignore_warnings=False
    When
        calling checkpoint_network_delete_command
    Then
        validate delete_network is called with ignore_warnings=False
    """
    from CheckPointFirewallV2 import checkpoint_network_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_network.return_value = {"message": "OK"}
    checkpoint_network_delete_command(mocked_client, identifier="test-network", ignore_warnings="false")
    mocked_client.delete_network.assert_called_once_with("test-network", False)


# ==================== Service Commands Tests ====================


def test_checkpoint_service_get_command(mocker):
    """
    Given
        a mocked client with a show_service response
    When
        calling checkpoint_service_get_command with service_type='tcp'
    Then
        validate the outputs contain the expected service data
    """
    from CheckPointFirewallV2 import checkpoint_service_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_service_tcp.json")
    mocked_client.show_service.return_value = mock_response
    result = checkpoint_service_get_command(mocked_client, identifier="test-tcp-service", service_type="tcp")
    assert result.outputs.get("name") == "test-tcp-service"
    assert result.outputs.get("uid") == "svc-tcp-uid-1234"
    assert result.outputs.get("type") == "service-tcp"
    assert result.outputs_prefix == "CheckPoint.TCPService"


@pytest.mark.parametrize(
    "service_type,expected_prefix",
    [
        ("tcp", "CheckPoint.TCPService"),
        ("udp", "CheckPoint.UDPService"),
        ("icmp", "CheckPoint.ICMPService"),
    ],
)
def test_checkpoint_service_get_command_types(mocker, service_type, expected_prefix):
    """
    Given
        a mocked client with a show_service response
    When
        calling checkpoint_service_get_command with different service types
    Then
        validate the correct outputs_prefix is used for each type
    """
    from CheckPointFirewallV2 import checkpoint_service_get_command

    mocked_client = mocker.Mock()
    mock_response = {"uid": "svc-uid", "name": "test-svc", "type": f"service-{service_type}", "groups": []}
    mocked_client.show_service.return_value = mock_response
    result = checkpoint_service_get_command(mocked_client, identifier="test-svc", service_type=service_type)
    assert result.outputs_prefix == expected_prefix
    mocked_client.show_service.assert_called_once_with("test-svc", service_type)


def test_checkpoint_service_list_command(mocker):
    """
    Given
        a mocked client with a list_services response
    When
        calling checkpoint_service_list_command with service_type='tcp'
    Then
        validate the outputs contain the expected list of services
    """
    from CheckPointFirewallV2 import checkpoint_service_list_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_services_tcp.json")
    mocked_client.list_services.return_value = mock_response
    result = checkpoint_service_list_command(mocked_client, service_type="tcp", limit=50, offset=0)
    assert len(result.outputs) == 2
    assert result.outputs[0].get("name") == "test-tcp-service-1"
    assert result.outputs[1].get("name") == "test-tcp-service-2"
    assert result.outputs_prefix == "CheckPoint.TCPService"


def test_checkpoint_service_list_command_with_identifier(mocker):
    """
    Given
        a mocked client with a show_service response
    When
        calling checkpoint_service_list_command with an identifier
    Then
        validate show_service is called instead of list_services
    """
    from CheckPointFirewallV2 import checkpoint_service_list_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_service_tcp.json")
    mocked_client.show_service.return_value = mock_response
    result = checkpoint_service_list_command(mocked_client, service_type="tcp", identifier="test-tcp-service")
    assert result.outputs.get("name") == "test-tcp-service"
    mocked_client.show_service.assert_called_once_with("test-tcp-service", "tcp")
    mocked_client.list_services.assert_not_called()


def test_checkpoint_service_list_command_empty(mocker):
    """
    Given
        a mocked client with an empty list_services response
    When
        calling checkpoint_service_list_command
    Then
        validate the readable output indicates no services found
    """
    from CheckPointFirewallV2 import checkpoint_service_list_command

    mocked_client = mocker.Mock()
    mocked_client.list_services.return_value = {"total": 0, "objects": []}
    result = checkpoint_service_list_command(mocked_client, service_type="tcp", limit=50, offset=0)
    assert result.readable_output == "No tcp service objects were found."
    assert result.outputs == []


def test_checkpoint_tcp_service_add_command(mocker):
    """
    Given
        a mocked client with an add_service_tcp response
    When
        calling checkpoint_tcp_service_add_command
    Then
        validate the outputs contain the expected TCP service data
    """
    from CheckPointFirewallV2 import checkpoint_tcp_service_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_service_tcp.json")
    mocked_client.add_service_tcp.return_value = mock_response
    result = checkpoint_tcp_service_add_command(mocked_client, identifier="test-tcp-service", port="8080")
    assert result.outputs.get("name") == "test-tcp-service"
    assert result.outputs.get("uid") == "svc-tcp-uid-1234"
    assert result.outputs_prefix == "CheckPoint.TCPService"
    mocked_client.add_service_tcp.assert_called_once_with(
        identifier="test-tcp-service",
        port="8080",
        comments=None,
        color=None,
        session_timeout=None,
        tags=None,
    )


def test_checkpoint_udp_service_add_command(mocker):
    """
    Given
        a mocked client with an add_service_udp response
    When
        calling checkpoint_udp_service_add_command
    Then
        validate the outputs contain the expected UDP service data
    """
    from CheckPointFirewallV2 import checkpoint_udp_service_add_command

    mocked_client = mocker.Mock()
    mock_response = {
        "uid": "svc-udp-uid-1234",
        "name": "test-udp-service",
        "type": "service-udp",
        "port": "53",
        "groups": [],
        "domain": {"uid": "domain-uid", "name": "SMC User", "domain-type": "domain"},
        "meta-info": {"creator": "admin", "last-modifier": "admin"},
        "read-only": False,
    }
    mocked_client.add_service_udp.return_value = mock_response
    result = checkpoint_udp_service_add_command(mocked_client, identifier="test-udp-service", port="53")
    assert result.outputs.get("name") == "test-udp-service"
    assert result.outputs.get("uid") == "svc-udp-uid-1234"
    assert result.outputs_prefix == "CheckPoint.UDPService"


def test_checkpoint_icmp_service_add_command(mocker):
    """
    Given
        a mocked client with an add_service_icmp response
    When
        calling checkpoint_icmp_service_add_command
    Then
        validate the outputs contain the expected ICMP service data
    """
    from CheckPointFirewallV2 import checkpoint_icmp_service_add_command

    mocked_client = mocker.Mock()
    mock_response = {
        "uid": "svc-icmp-uid-1234",
        "name": "test-icmp-service",
        "type": "service-icmp",
        "icmp-type": 8,
        "icmp-code": 0,
        "groups": [],
        "domain": {"uid": "domain-uid", "name": "SMC User", "domain-type": "domain"},
        "meta-info": {"creator": "admin", "last-modifier": "admin"},
        "read-only": False,
    }
    mocked_client.add_service_icmp.return_value = mock_response
    result = checkpoint_icmp_service_add_command(mocked_client, identifier="test-icmp-service", icmp_type="8", icmp_code="0")
    assert result.outputs.get("name") == "test-icmp-service"
    assert result.outputs.get("uid") == "svc-icmp-uid-1234"
    assert result.outputs_prefix == "CheckPoint.ICMPService"
    mocked_client.add_service_icmp.assert_called_once_with(
        identifier="test-icmp-service",
        icmp_type=8,
        icmp_code=0,
        comments=None,
        color=None,
        tags=None,
    )


def test_checkpoint_tcp_service_update_command(mocker):
    """
    Given
        a mocked client with an update_service_tcp response
    When
        calling checkpoint_tcp_service_update_command
    Then
        validate the outputs contain the expected updated TCP service data
    """
    from CheckPointFirewallV2 import checkpoint_tcp_service_update_command

    mocked_client = mocker.Mock()
    mock_response = {
        "uid": "svc-tcp-uid-1234",
        "name": "updated-tcp-service",
        "type": "service-tcp",
        "port": "9090",
        "groups": [],
        "comments": "updated",
        "domain": {"uid": "domain-uid", "name": "SMC User", "domain-type": "domain"},
        "meta-info": {"creator": "admin", "last-modifier": "admin"},
        "read-only": False,
    }
    mocked_client.update_service_tcp.return_value = mock_response
    result = checkpoint_tcp_service_update_command(
        mocked_client, identifier="test-tcp-service", new_identifier="updated-tcp-service", port="9090"
    )
    assert result.outputs.get("name") == "updated-tcp-service"
    assert result.outputs.get("uid") == "svc-tcp-uid-1234"
    assert result.outputs_prefix == "CheckPoint.TCPService"


def test_checkpoint_udp_service_update_command(mocker):
    """
    Given
        a mocked client with an update_service_udp response
    When
        calling checkpoint_udp_service_update_command
    Then
        validate the outputs contain the expected updated UDP service data
    """
    from CheckPointFirewallV2 import checkpoint_udp_service_update_command

    mocked_client = mocker.Mock()
    mock_response = {
        "uid": "svc-udp-uid-1234",
        "name": "updated-udp-service",
        "type": "service-udp",
        "port": "5353",
        "groups": [],
        "domain": {"uid": "domain-uid", "name": "SMC User", "domain-type": "domain"},
        "meta-info": {"creator": "admin", "last-modifier": "admin"},
        "read-only": False,
    }
    mocked_client.update_service_udp.return_value = mock_response
    result = checkpoint_udp_service_update_command(
        mocked_client, identifier="test-udp-service", new_identifier="updated-udp-service", port="5353"
    )
    assert result.outputs.get("name") == "updated-udp-service"
    assert result.outputs_prefix == "CheckPoint.UDPService"


def test_checkpoint_icmp_service_update_command(mocker):
    """
    Given
        a mocked client with an update_service_icmp response
    When
        calling checkpoint_icmp_service_update_command
    Then
        validate the outputs contain the expected updated ICMP service data
    """
    from CheckPointFirewallV2 import checkpoint_icmp_service_update_command

    mocked_client = mocker.Mock()
    mock_response = {
        "uid": "svc-icmp-uid-1234",
        "name": "updated-icmp-service",
        "type": "service-icmp",
        "icmp-type": 0,
        "icmp-code": 0,
        "groups": [],
        "domain": {"uid": "domain-uid", "name": "SMC User", "domain-type": "domain"},
        "meta-info": {"creator": "admin", "last-modifier": "admin"},
        "read-only": False,
    }
    mocked_client.update_service_icmp.return_value = mock_response
    result = checkpoint_icmp_service_update_command(
        mocked_client, identifier="test-icmp-service", new_identifier="updated-icmp-service", icmp_type="0", icmp_code="0"
    )
    assert result.outputs.get("name") == "updated-icmp-service"
    assert result.outputs_prefix == "CheckPoint.ICMPService"
    mocked_client.update_service_icmp.assert_called_once_with(
        identifier="test-icmp-service",
        new_identifier="updated-icmp-service",
        icmp_type=0,
        icmp_code=0,
        comments=None,
        color=None,
        tags=None,
    )


def test_checkpoint_service_delete_command(mocker):
    """
    Given
        a mocked client
    When
        calling checkpoint_service_delete_command
    Then
        validate the readable output indicates successful deletion
    """
    from CheckPointFirewallV2 import checkpoint_service_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_service.return_value = {"message": "OK"}
    result = checkpoint_service_delete_command(mocked_client, identifier="test-tcp-service", service_type="tcp")
    assert result.readable_output == "Service deleted successfully."
    mocked_client.delete_service.assert_called_once_with("test-tcp-service", "tcp", False)


def test_checkpoint_service_delete_command_with_ignore_warnings(mocker):
    """
    Given
        a mocked client with ignore_warnings=True
    When
        calling checkpoint_service_delete_command
    Then
        validate delete_service is called with ignore_warnings=True
    """
    from CheckPointFirewallV2 import checkpoint_service_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_service.return_value = {"message": "OK"}
    checkpoint_service_delete_command(mocked_client, identifier="test-tcp-service", service_type="udp", ignore_warnings="true")
    mocked_client.delete_service.assert_called_once_with("test-tcp-service", "udp", True)


# ==================== NAT Rule Commands Tests ====================


def test_checkpoint_nat_rule_get_command(mocker):
    """
    Given
        a mocked client with a show_nat_rule response
    When
        calling checkpoint_nat_rule_get_command
    Then
        validate the outputs contain the expected NAT rule data
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_get_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_nat_rule.json")
    mocked_client.show_nat_rule.return_value = mock_response
    result = checkpoint_nat_rule_get_command(mocked_client, identifier="test-nat-rule", package="Standard")
    assert result.outputs.get("name") == "test-nat-rule"
    assert result.outputs.get("uid") == "nat-rule-uid-1234"
    assert result.outputs.get("type") == "nat-rule"
    assert result.outputs_prefix == "CheckPoint.NatRule"
    mocked_client.show_nat_rule.assert_called_once_with("test-nat-rule", "Standard")


def test_checkpoint_nat_rule_list_command(mocker):
    """
    Given
        a mocked client with a list_nat_rulebase response
    When
        calling checkpoint_nat_rule_list_command
    Then
        validate the outputs contain the expected list of NAT rules
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_list_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/list_nat_rulebase.json")
    mocked_client.list_nat_rulebase.return_value = mock_response
    result = checkpoint_nat_rule_list_command(mocked_client, package="Standard")
    assert len(result.outputs) == 2
    assert result.outputs[0].get("name") == "nat-rule-1"
    assert result.outputs[1].get("name") == "nat-rule-2"
    assert result.outputs_prefix == "CheckPoint.NatRule"


def test_checkpoint_nat_rule_list_command_empty(mocker):
    """
    Given
        a mocked client with an empty list_nat_rulebase response
    When
        calling checkpoint_nat_rule_list_command
    Then
        validate the readable output indicates no NAT rules found
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_list_command

    mocked_client = mocker.Mock()
    mocked_client.list_nat_rulebase.return_value = {"total": 0, "rulebase": []}
    result = checkpoint_nat_rule_list_command(mocked_client, package="Standard")
    assert result.readable_output == "No NAT rules were found."
    assert result.outputs == []


def test_checkpoint_nat_rule_list_command_with_sections(mocker):
    """
    Given
        a mocked client with a list_nat_rulebase response containing nested sections
    When
        calling checkpoint_nat_rule_list_command
    Then
        validate the outputs correctly extract nat-rule entries from nested sections
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_list_command

    mocked_client = mocker.Mock()
    mock_response = {
        "total": 2,
        "rulebase": [
            {
                "uid": "section-uid",
                "type": "nat-section",
                "name": "test-section",
                "rulebase": [
                    {"uid": "nested-nat-uid-1", "name": "nested-nat-1", "type": "nat-rule", "enabled": True},
                    {"uid": "nested-nat-uid-2", "name": "nested-nat-2", "type": "nat-rule", "enabled": False},
                ],
            }
        ],
    }
    mocked_client.list_nat_rulebase.return_value = mock_response
    result = checkpoint_nat_rule_list_command(mocked_client, package="Standard")
    assert len(result.outputs) == 2
    assert result.outputs[0].get("name") == "nested-nat-1"
    assert result.outputs[1].get("name") == "nested-nat-2"


def test_checkpoint_nat_rule_add_command(mocker):
    """
    Given
        a mocked client with an add_nat_rule response
    When
        calling checkpoint_nat_rule_add_command
    Then
        validate the outputs contain the expected NAT rule data
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_add_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/add_nat_rule.json")
    mocked_client.add_nat_rule.return_value = mock_response
    result = checkpoint_nat_rule_add_command(
        mocked_client,
        package="Standard",
        position="top",
        name="new-nat-rule",
        original_source="Any",
        translated_destination="internal-server",
    )
    assert result.outputs.get("name") == "new-nat-rule"
    assert result.outputs.get("uid") == "nat-rule-uid-new-1234"
    assert result.outputs_prefix == "CheckPoint.NatRule"


def test_checkpoint_nat_rule_add_command_args(mocker):
    """
    Given
        a mocked client
    When
        calling checkpoint_nat_rule_add_command with various arguments
    Then
        validate add_nat_rule is called with the correct arguments
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_add_command

    mocked_client = mocker.Mock()
    mocked_client.add_nat_rule.return_value = {"uid": "test-uid", "type": "nat-rule"}
    checkpoint_nat_rule_add_command(
        mocked_client,
        package="Standard",
        position="bottom",
        name="test-rule",
        original_source="src-obj",
        original_destination="dst-obj",
        original_service="svc-obj",
        translated_source="tsrc-obj",
        translated_destination="tdst-obj",
        translated_service="tsvc-obj",
        enabled="true",
        nat_method="static",
    )
    mocked_client.add_nat_rule.assert_called_once_with(
        package="Standard",
        position="bottom",
        name="test-rule",
        original_source="src-obj",
        original_destination="dst-obj",
        original_service="svc-obj",
        translated_source="tsrc-obj",
        translated_destination="tdst-obj",
        translated_service="tsvc-obj",
        install_on=None,
        comments=None,
        enabled=True,
        method="static",
        tags=None,
    )


def test_checkpoint_nat_rule_update_command(mocker):
    """
    Given
        a mocked client with an update_nat_rule response
    When
        calling checkpoint_nat_rule_update_command
    Then
        validate the outputs contain the expected updated NAT rule data
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_update_command

    mocked_client = mocker.Mock()
    mock_response = util_load_json("test_data/show_nat_rule.json")
    mocked_client.update_nat_rule.return_value = mock_response
    result = checkpoint_nat_rule_update_command(
        mocked_client,
        identifier="test-nat-rule",
        package="Standard",
        original_source="new-source",
        comments="updated rule",
    )
    assert result.outputs.get("name") == "test-nat-rule"
    assert result.outputs.get("uid") == "nat-rule-uid-1234"
    assert result.outputs_prefix == "CheckPoint.NatRule"


def test_checkpoint_nat_rule_delete_command(mocker):
    """
    Given
        a mocked client
    When
        calling checkpoint_nat_rule_delete_command
    Then
        validate the readable output indicates successful deletion
    """
    from CheckPointFirewallV2 import checkpoint_nat_rule_delete_command

    mocked_client = mocker.Mock()
    mocked_client.delete_nat_rule.return_value = {"message": "OK"}
    result = checkpoint_nat_rule_delete_command(mocked_client, identifier="test-nat-rule", package="Standard")
    assert result.readable_output == "Nat Rule deleted successfully."
    mocked_client.delete_nat_rule.assert_called_once_with(identifier="test-nat-rule", package="Standard")


# ==================== Helper Function Tests ====================


def test_build_nat_settings_all_none():
    """
    Given
        all None arguments
    When
        calling build_nat_settings
    Then
        validate None is returned
    """
    from CheckPointFirewallV2 import build_nat_settings

    result = build_nat_settings(
        nat_settings_auto_rule=None,
        nat_method=None,
        nat_hide_behind=None,
        nat_install_on=None,
        nat_settings_ip=None,
    )
    assert result is None


def test_build_nat_settings_hide_method():
    """
    Given
        nat_method='hide' and nat_hide_behind='gateway'
    When
        calling build_nat_settings
    Then
        validate the correct nat-settings dict is returned
    """
    from CheckPointFirewallV2 import build_nat_settings

    result = build_nat_settings(
        nat_settings_auto_rule=True,
        nat_method="hide",
        nat_hide_behind="gateway",
        nat_install_on=None,
        nat_settings_ip=None,
    )
    assert result == {"auto-rule": True, "method": "hide", "hide-behind": "gateway"}


def test_build_nat_settings_static_method():
    """
    Given
        nat_method='static' with an IP address
    When
        calling build_nat_settings
    Then
        validate the correct nat-settings dict is returned
    """
    from CheckPointFirewallV2 import build_nat_settings

    result = build_nat_settings(
        nat_settings_auto_rule=True,
        nat_method="static",
        nat_hide_behind=None,
        nat_install_on="gw-1",
        nat_settings_ip="10.0.0.1",
    )
    assert result == {"auto-rule": True, "method": "static", "install-on": "gw-1", "ipv4-address": "10.0.0.1"}


def test_build_nat_settings_static_with_hide_behind_raises():
    """
    Given
        nat_method='static' and nat_hide_behind='gateway'
    When
        calling build_nat_settings
    Then
        validate a ValueError is raised
    """
    from CheckPointFirewallV2 import build_nat_settings

    with pytest.raises(ValueError, match="forbidden"):
        build_nat_settings(
            nat_settings_auto_rule=True,
            nat_method="static",
            nat_hide_behind="gateway",
            nat_install_on=None,
            nat_settings_ip=None,
        )


def test_build_nat_settings_hide_gateway_with_ip_raises():
    """
    Given
        nat_method='hide', nat_hide_behind='gateway', and nat_settings_ip provided
    When
        calling build_nat_settings
    Then
        validate a ValueError is raised
    """
    from CheckPointFirewallV2 import build_nat_settings

    with pytest.raises(ValueError, match="must not be provided"):
        build_nat_settings(
            nat_settings_auto_rule=True,
            nat_method="hide",
            nat_hide_behind="gateway",
            nat_install_on=None,
            nat_settings_ip="10.0.0.1",
        )

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


def test_list_hosts_with_details_level_full_and_domains_to_process_raises(mocker):
    """
    Given
        details_level set to 'full' and domains_to_process provided
    When
        calling checkpoint_list_hosts_command
    Then
        validate a ValueError is raised by validate_domains_to_process
    """
    from CheckPointFirewallV2 import checkpoint_list_hosts_command

    mocked_client = mocker.Mock()

    with pytest.raises(ValueError, match="cannot be used with 'details_level' set to 'full'"):
        checkpoint_list_hosts_command(mocked_client, 50, 0, details_level="full", domains_to_process="domain1,domain2")

    mocked_client.list_hosts.assert_not_called()


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

import json
import os
from urllib.parse import urljoin

import demistomock as demisto
from ForescoutEyeInspect import Client

CLIENT_BASE_URL = "https://api.com/"
MOCK_BASE_URL = urljoin(CLIENT_BASE_URL, "api/v1")


def load_json_mock_response(filename: str) -> str:
    with open(os.path.join("test_data", f"{filename}.json")) as test_file:
        return json.loads(test_file.read())


def load_raw_mock_response(filename: str) -> bytes:
    with open(os.path.join("test_data", filename), "rb") as test_file:
        return test_file.read()


def mock_client() -> Client:
    return Client(base_url=CLIENT_BASE_URL, use_ssl=False, use_proxy=False, username="", password="")


def mock_csrf_token(requests_mock):
    requests_mock.get(f"{MOCK_BASE_URL}/sensors",
                      headers={
                          "CCJSESSIONID": os.urandom(32).hex().upper(),
                          "X-CSRF-Token": os.urandom(32).hex().upper()
                      })


def test_list_hosts(requests_mock):
    """
    Scenario: Retrieves information about the hosts in the eyeInspect CC database.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-host-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_hosts_command

    client = mock_client()
    mock_response = load_json_mock_response("hosts")

    requests_mock.get(f"{MOCK_BASE_URL}/hosts", json=mock_response)

    result = list_hosts_command(client, {"page": 1, "limit": 50})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.Host"

    assert result.outputs[0]["id"] == 1
    assert result.outputs[0]["ip"] == "192.168.1.2"
    assert result.outputs[0]["mac_addresses"][0] == "00:0C:29:6D:35:12"


def test_list_links(requests_mock):
    """
    Scenario: Retrieves information about the links in the eyeInspect CC database.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-link-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_links_command

    client = mock_client()
    mock_response = load_json_mock_response("links")

    requests_mock.get(f"{MOCK_BASE_URL}/links", json=mock_response)

    result = list_links_command(client, {"page": 1, "limit": 50})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.Link"

    assert result.outputs[0]["id"] == 1
    assert result.outputs[0]["src_host_id"] == 1
    assert result.outputs[0]["dst_host_id"] == 2
    assert result.outputs[0]["tx_bytes"] == 35680158
    assert result.outputs[0]["ports"][0] == 502


def test_get_vulnerability_info(requests_mock):
    """
    Scenario: Retrieves information about a specific vulnerability stored in the eyeInspect CC database.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-vulnerability-info-get command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_vulnerability_info_command

    client = mock_client()
    mock_response = load_json_mock_response("cve")

    requests_mock.get(f"{MOCK_BASE_URL}/cve_info/CVE-2020-0305", json=mock_response)

    result = get_vulnerability_info_command(client, {"cve_id": "CVE-2020-0305"})

    assert result.outputs_prefix == "ForescoutEyeInspect.CVE"

    assert result.outputs["id"] == "CVE-2020-0305"
    assert result.outputs["cve_id"] == "CVE-2020-0305"
    assert result.outputs["published_date"] == "2018-11-27T01:00:00.000+01:00"
    assert result.outputs["cvss_score"] == 4.4
    assert result.outputs["cvss_access_vector"] == "LOCAL"


def test_list_alerts(requests_mock):
    """
    Scenario: Retrieves information about the alerts inside eyeInspect CC.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-alert-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_alerts_command

    client = mock_client()
    mock_response = load_json_mock_response("alerts")

    requests_mock.get(f"{MOCK_BASE_URL}/alerts", json=mock_response)

    result = list_alerts_command(client, {"page": 1, "limit": 1})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.Alert"

    assert result.outputs[0]["alert_id"] == 1
    assert result.outputs[0]["timestamp"] == "2022-02-03T07:49:50.092+01:00"
    assert result.outputs[0]["event_type_ids"][0] == "ps_tcp_ack"
    assert result.outputs[0]["l3_proto"] == "IP"
    assert result.outputs[0]["dst_ip"] == "192.168.92.12"


def test_get_alert_pcap(requests_mock):
    """
    Scenario: Retrieves the PCAP file associated to a given Alert.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-alert-pcap-get command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_alert_pcap_command

    client = mock_client()
    mock_response = load_raw_mock_response("alert.pcap")

    requests_mock.get(f"{MOCK_BASE_URL}/alert_pcaps/1", content=mock_response)

    result = get_alert_pcap_command(client, {"alert_id": 1})
    saved_filename = f'{demisto.investigation()["id"]}_{result["FileID"]}'

    assert result["File"] == "alert_1_sniff.pcap"
    assert result["ContentsFormat"] == "text"
    assert os.path.isfile(saved_filename)

    os.remove(saved_filename)


def test_list_sensors(requests_mock):
    """
    Scenario: Retrieves information about the sensors associated to the eyeInspect CC.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-sensor-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_sensors_command

    client = mock_client()
    mock_response = load_json_mock_response("sensors")

    requests_mock.get(f"{MOCK_BASE_URL}/sensors", json=mock_response)

    result = list_sensors_command(client, {"page": 1, "limit": 50})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.Sensor"

    assert result.outputs[0]["id"] == 2
    assert result.outputs[0]["name"] == "sensor1"
    assert result.outputs[0]["health_status"]["memory_usage"]["level"] == "NORMAL"


def test_list_sensor_modules(requests_mock):
    """
    Scenario: Retrieves information about the Modules of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-sensor-module-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_sensor_modules_command

    client = mock_client()
    mock_response = load_json_mock_response("sensor_modules")

    requests_mock.get(f"{MOCK_BASE_URL}/sensors/2/modules", json=mock_response)

    result = list_sensor_modules_command(client, {"sensor_id": 2, "page": 1, "limit": 50})

    assert len(result.outputs) == 9
    assert result.outputs_prefix == "ForescoutEyeInspect.SensorModule"

    assert result.outputs[0]["id"] == 1
    assert result.outputs[0]["sensor_id"] == 2
    assert result.outputs[0]["singleton"]
    assert result.outputs[0]["name"] == "Industrial threat library (ITL)"


def test_update_sensor_module(requests_mock):
    """
    Scenario: Changes the specified properties of the specified Module.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-sensor-module-update command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import update_sensor_module_command

    client = mock_client()
    mock_response = load_json_mock_response("sensor_module")

    mock_csrf_token(requests_mock)
    requests_mock.put(f"{MOCK_BASE_URL}/sensors/2/modules/5", json=mock_response)

    result = update_sensor_module_command(
        client,
        {
            "sensor_id": 2,
            "module_id": 5,
            "name": "PORTSCAN",
            "description": "Port scanning",
            "started": True,
            "operational_mode": "Learning",
        },
    )

    assert result.outputs_prefix == "ForescoutEyeInspect.SensorModule"

    assert result.outputs["id"] == 5
    assert result.outputs["sensor_id"] == 2
    assert result.outputs["singleton"]
    assert result.outputs["name"] == "Portscan"


def test_delete_sensor_module(requests_mock):
    """
    Scenario: Deletes the specified Module from the specified Sensor and from the eyeInspect CC database.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-sensor-module-delete command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import delete_sensor_module_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.delete(f"{MOCK_BASE_URL}/sensors/2/modules/5", text="")

    result = delete_sensor_module_command(client, {"sensor_id": 2, "module_id": 5})

    assert result.readable_output == "## The module 5 of sensor 2 was successfully deleted!"


def test_get_ip_blacklist(requests_mock):
    """
    Scenario: Retrieves the IP blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-ip-blacklist-get command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_ip_blacklist_command

    client = mock_client()
    mock_response = load_json_mock_response("ip_blacklist")

    requests_mock.get(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_bip/blacklist", json=mock_response)

    result = get_ip_blacklist_command(client, {"sensor_id": 2, "page": 1, "limit": 50})

    assert result.outputs_prefix == "ForescoutEyeInspect.IPBlacklist"
    assert result.outputs[0]["address"] == "1.160.139.122"
    assert result.outputs[0]["comment"] == "North Korean Trojan"


def test_add_ip_blacklist(requests_mock):
    """
    Scenario: Adds a new entry to the IP blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-ip-blacklist-add command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import add_ip_blacklist_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_bip/blacklist", text="")

    result = add_ip_blacklist_command(client, {
        "sensor_id": 2,
        "address": "1.2.3.4",
        "comment": "Malicious IP address"
    })

    assert "1.2.3.4" in result.readable_output
    assert "Malicious IP address" in result.readable_output


def test_get_domain_blacklist(requests_mock):
    """
    Scenario: Retrieves the domain name blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-domain-blacklist-get command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_domain_blacklist_command

    client = mock_client()
    mock_response = load_json_mock_response("domain_blacklist")

    requests_mock.get(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_dns_bd/blacklist", json=mock_response)

    result = get_domain_blacklist_command(client, {"sensor_id": 2, "page": 1, "limit": 50})

    assert result.outputs_prefix == "ForescoutEyeInspect.DomainBlacklist"

    assert result.outputs[0]["domain_name"] == "028xmz.com"
    assert result.outputs[0]["comment"] == "URL used by North-Korean Trojan COPPERHEDGE"


def test_add_domain_blacklist(requests_mock):
    """
    Scenario: Adds a new entry to the domain name blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-domain-blacklist-add command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import add_domain_blacklist_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_dns_bd/blacklist", text="")

    result = add_domain_blacklist_command(client, {
        "sensor_id": 2,
        "domain_name": "xyz.com",
        "comment": "Malicious domain"
    })

    assert "xyz.com" in result.readable_output
    assert "Malicious domain" in result.readable_output


def test_get_ssl_client_blacklist(requests_mock):
    """
    Scenario: Retrieves the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-ssl-client-blacklist-get command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_ssl_client_blacklist_command

    client = mock_client()
    mock_response = load_json_mock_response("ssl_client_blacklist")

    requests_mock.get(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_ssl_bja3/blacklist",
                      json=mock_response)

    result = get_ssl_client_blacklist_command(client, {"sensor_id": 2, "page": 1, "limit": 50})

    assert result.outputs_prefix == "ForescoutEyeInspect.SSLClientBlacklist"

    assert result.outputs[0]["application_name"] == "ShadowServer Scanner"
    assert result.outputs[0]["ja3_hash"] == "0ad94fcb7d3a2c56679fbd004f6b12cd"
    assert result.outputs[0]["comment"] == ""


def test_add_ssl_client_blacklist(requests_mock):
    """
    Scenario: Adds a new entry to the SSL client application blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-ssl-client-blacklist-add command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import add_ssl_client_blacklist_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_ssl_bja3/blacklist", text="")

    result = add_ssl_client_blacklist_command(
        client,
        {
            "sensor_id": 2,
            "application_name": "Shodan",
            "ja3_hash": "0add6ceb611a7613f97329af3b6828d9",
            "comment": "Malicious site",
        },
    )

    assert "Shodan" in result.readable_output
    assert "0add6ceb611a7613f97329af3b6828d9" in result.readable_output
    assert "Malicious site" in result.readable_output


def test_get_file_operation_blacklist(requests_mock):
    """
    Scenario: Retrieves the file operation blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-file-operation-blacklist-get command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_file_operation_blacklist_command

    client = mock_client()
    mock_response = load_json_mock_response("file_operation_blacklist")
    requests_mock.get(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_bfo/blacklist", json=mock_response)

    result = get_file_operation_blacklist_command(client, {"sensor_id": 2, "page": 1, "limit": 50})

    assert result.outputs_prefix == "ForescoutEyeInspect.FileOperationBlacklist"

    assert result.outputs[0]["matching_type"] == "REGEX"
    assert result.outputs[0]["file_or_folder"] == "\\.accdb$"
    assert result.outputs[0]["operation"] == "WRITE"
    assert result.outputs[0]["comment"] == "Access 2007 Database File."


def test_add_file_operation_blacklist(requests_mock):
    """
    Scenario: Adds entries to the file operation blacklist from the Industrial Threat Library of the specified Sensor.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-file-operation-blacklist-add command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import add_file_operation_blacklist_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/sensors/2/itl/itl_sec_udb_bfo/blacklist", text="")

    result = add_file_operation_blacklist_command(
        client,
        {
            "sensor_id": 2,
            "matching_type": "REGEX",
            "file_or_folder": "\\.accdb$",
            "operation": "WRITE",
            "comment": "Access 2007 Database File.",
        },
    )

    assert "REGEX" in result.readable_output
    assert "\\.accdb$" in result.readable_output
    assert "WRITE" in result.readable_output
    assert "Access 2007 Database File." in result.readable_output


def test_get_diagnostics_information(requests_mock):
    """
    Scenario: Retrieves information about all monitored Command Center resources and their health status excluding the logs.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-diagnostics-information-get command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_diagnostics_information_command

    client = mock_client()
    mock_response = load_json_mock_response("cc_info")

    requests_mock.get(f"{MOCK_BASE_URL}/cc_info", json=mock_response)

    result = get_diagnostics_information_command(client)

    assert result.outputs_prefix == "ForescoutEyeInspect.CCInfo"

    assert result.outputs["ip_address"] == "192.168.1.2"
    assert result.outputs["open_ports"][0] == "443"
    assert result.outputs["health_status"]["disk_usage"][0]["current_value"] == "7%"


def test_get_diagnostic_logs(requests_mock):
    """
    Scenario: Download the ZIP file which contains diagnostic logs of the Command Center.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-diagnostic-log-get command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import get_diagnostic_logs_command

    client = mock_client()
    mock_response = load_raw_mock_response("diagnostic_logs.zip")

    requests_mock.get(f"{MOCK_BASE_URL}/diagnostic_logs", content=mock_response)

    result = get_diagnostic_logs_command(client, {"cc_info": True, "sensor_id": 2})
    saved_filename = f'{demisto.investigation()["id"]}_{result["FileID"]}'

    assert result["File"] == "command_center_diagnostic_logs.zip"
    assert os.path.isfile(saved_filename)

    os.remove(saved_filename)


def test_list_group_policies(requests_mock):
    """
    Scenario: Get all group policies.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_group_policies_command

    client = mock_client()
    mock_response = load_json_mock_response("group_policies")

    requests_mock.get(f"{MOCK_BASE_URL}/group_policy", json=mock_response)

    result = list_group_policies_command(client, {"page": 1, "limit": 50})

    assert result.outputs_prefix == "ForescoutEyeInspect.GroupPolicy"

    assert result.outputs[0]["id"] == 1
    assert result.outputs[0]["name"] == "Test Policy"
    assert result.outputs[0]["constraints"][0]["type"] == "os_version"


def test_create_group_policy(requests_mock):
    """
    Scenario: Create a group policy.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-create command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import create_group_policy_command

    client = mock_client()
    mock_response = load_json_mock_response("group_policy")

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/group_policy", json=mock_response)

    result = create_group_policy_command(
        client,
        {
            "name": "Allow MODBUS TCP Policy",
            "description": "Allow MODBUS TCP traffic",
            "constraints": {
                "type": "os_version",
                "operator": "equals",
                "os_version": "1.2.3"
            },
        },
    )

    assert result.outputs_prefix == "ForescoutEyeInspect.GroupPolicy"

    assert result.outputs["id"] == 1
    assert result.outputs["name"] == "Test Policy"
    assert result.outputs["constraints"][0]["type"] == "os_version"


def test_update_group_policy(requests_mock):
    """
    Scenario: Update a group policy.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-update command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import update_group_policy_command

    client = mock_client()
    mock_response = load_json_mock_response("group_policy")

    mock_csrf_token(requests_mock)
    requests_mock.put(f"{MOCK_BASE_URL}/group_policy/1", json=mock_response)

    result = update_group_policy_command(
        client,
        {
            "policy_id": 1,
            "name": "Allow MODBUS TCP",
            "description": "Allow MODBUS TCP traffic",
            "constraints": {
                "type": "os_version",
                "operator": "equals",
                "os_version": "1.2.3"
            },
        },
    )

    assert result.outputs_prefix == "ForescoutEyeInspect.GroupPolicy"

    assert result.outputs["id"] == 1
    assert result.outputs["name"] == "Test Policy"
    assert result.outputs["constraints"] == [{
        "operator": "equals",
        "os_version": "1.2.3",
        "type": "os_version"
    }]


def test_delete_group_policy(requests_mock):
    """
    Scenario: Delete a group policy.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-delete command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import delete_group_policy_command

    client = mock_client()
    mock_response = load_json_mock_response("group_policy")

    mock_csrf_token(requests_mock)
    requests_mock.delete(f"{MOCK_BASE_URL}/group_policy/1", json=mock_response)

    result = delete_group_policy_command(client, {"policy_id": 1})

    assert result.readable_output == "## The group policy 1 was successfully deleted!"


def test_assign_group_policy_hosts(requests_mock):
    """
    Scenario: Add all hosts not assigned to any policy (individual or group) matching the filter to the group policy.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-host-assign command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import assign_group_policy_hosts_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/group_policy/1/add_hosts", json={"count": 2})

    result = assign_group_policy_hosts_command(client, {
        "policy_id": 1,
        "filter_type": "address",
        "filter_value": "192.168.1.5"
    })

    assert result.readable_output == "## 2 Additional Hosts Were Assigned to Group Policy 1!"


def test_unassign_group_policy_hosts(requests_mock):
    """
    Scenario: Unassign all hosts assigned to the group policy matching the filter.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-group-policy-host-unassign command is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import unassign_group_policy_hosts_command

    client = mock_client()

    mock_csrf_token(requests_mock)
    requests_mock.post(f"{MOCK_BASE_URL}/group_policy/1/remove_hosts", json={"count": 2})

    result = unassign_group_policy_hosts_command(client, {
        "policy_id": 1,
        "filter_type": "address",
        "filter_value": "192.168.1.5"
    })

    assert result.readable_output == "## 2 Additional Hosts Were Unassigned from Group Policy 1!"


def test_list_ip_reuse_domains(requests_mock):
    """
    Scenario: Get all IP reuse domains.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-ip-reuse-domain-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_ip_reuse_domains_command

    client = mock_client()
    mock_response = load_json_mock_response("ip_reuse_domains")

    requests_mock.get(f"{MOCK_BASE_URL}/ip_reuse_domains", json=mock_response)

    result = list_ip_reuse_domains_command(client, {"page": 1, "limit": 50})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.IPReuseDomain"

    assert result.outputs[0]["id"] == 1
    assert result.outputs[0]["name"] == "Default"
    assert result.outputs[0]["address"] == "-"
    assert result.outputs[0]["vlan_ids"] == "any"


def test_list_hosts_changelog(requests_mock):
    """
    Scenario: Retrieves information about the changes of host properties and configuration from the eyeInspect CC database.
    Given:
        - User has provided valid credentials.
    When:
        - forescout-ei-hosts-changelog-list command is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from ForescoutEyeInspect import list_hosts_changelog_command

    client = mock_client()
    mock_response = load_json_mock_response("host_change_logs")

    requests_mock.get(f"{MOCK_BASE_URL}/host_change_logs", json=mock_response)

    result = list_hosts_changelog_command(client, {"page": 1, "limit": 1})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "ForescoutEyeInspect.HostChangeLog"

    assert result.outputs[0]["id"] == 51
    assert result.outputs[0]["host_id"] == 49
    assert result.outputs[0]["old_value"] == ""
    assert result.outputs[0]["host_address"] == "192.168.60.192"
    assert result.outputs[0]["host_mac_addresses"][0] == "B4:2E:99:C9:5E:75"

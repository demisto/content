API_KEY = "API-KEY"
SERVER = "https://10.11.80.21:9443"
BASE_URL = SERVER + "/api/v2/"


INTEGRATION_PARAMS = {"apikey": API_KEY, "url": SERVER, "insecure": False, "issuetype": ["PANSecurityVulnerabilityChecks"]}

NETWORK_PORT_DOWN_ISSUE = {
    "headline": "Network port(s) down",
    "device_id": "e112e185-671b-44ad-89b3-3f399ec41b81",
    "alert_id": 49498,
    "unique_identifier": "cross_vendor_network_port_down",
    "alert_type": "UNAUTOREMEDIATABLE_ISSUE",
    "configuration_set_id": 3211,
    "acknowledged": False,
    "id": "b45bf800-acf6-45aa-92cd-9c977f7b7829",
    "alert_blocks": [
        {"header": "Description", "body": "One or more ports are down.", "type": "text", "position": 0},
        {"header": "Ports Affected", "items": [], "type": "items", "position": 1},
        {"header": "Remediation Steps", "body": "Review the cause for the ports being down.", "type": "text", "position": 2},
    ],
    "resolved": False,
    "revalidated_at": "2020-01-22T13:47:23.180Z",
    "evidence": {"ts": [], "snapshot": []},
    "severity": {"level": 0, "description": "CRITICAL"},
    "notes": [],
    "create_at": "2019-10-07T19:55:39.177Z",
    "updated_at": "2020-01-28T06:52:26.875Z",
}

PAN_VULNERABILITY_ISSUE = {
    "headline": "Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021",
    "device_id": "01178b51-b8af-4249-aecf-6e5b8da4a04f",
    "alert_id": 49517,
    "unique_identifier": "panos_vulnerability_pansa_20170021_rule",
    "alert_type": "UNAUTOREMEDIATABLE_ISSUE",
    "configuration_set_id": 3409,
    "acknowledged": True,
    "id": "7f0a5ded-571a-4ba0-835d-ba2f76469226",
    "alert_blocks": [
        {
            "header": "Remediation Steps",
            "body": "Palo Alto Networks recommends disabling DNS Proxy for those customers who are affected and are "
            "unable to apply the update.\nFor more information please review: "
            "https://securityadvisories.paloaltonetworks.com/Home/Detail/91",
            "type": "text",
            "position": 1,
        },
        {
            "header": "Description",
            "body": "A Remote Code Execution vulnerability exists in the PAN-OS DNS Proxy. This issue affects "
            "customers who have DNS Proxy enabled in PAN-OS. This issue affects both the Data and Management "
            "planes of the firewall. When DNS Proxy processes a specially crafted fully qualified domain "
            "names (FQDN), it is possible to execute code on the firewall. (Ref # PAN-77516 / CVE-2017-8390)."
            "\nVendor Severity Rating: Critical",
            "type": "text",
            "position": 0,
        },
    ],
    "resolved": False,
    "revalidated_at": "2020-02-08T19:08:14.373Z",
    "evidence": {"ts": [], "snapshot": []},
    "severity": {"level": 1, "description": "ERROR"},
    "notes": [],
    "create_at": "2019-10-07T19:55:41.344Z",
    "updated_at": "2020-02-04T21:25:03.289Z",
}

NO_NTP_SERVERS_ISSUE = {
    "headline": "No NTP servers configured",
    "device_id": "f72b077e-8762-4db9-b31b-9144bc3d880b",
    "alert_id": 49519,
    "unique_identifier": "cross_vendor_no_ntp_servers",
    "alert_type": "UNAUTOREMEDIATABLE_ISSUE",
    "configuration_set_id": 3234,
    "acknowledged": False,
    "id": "f0278a3f-3764-41f2-be94-2b4bd36113ed",
    "alert_blocks": [
        {
            "header": "Remediation Steps",
            "body": 'A workaround to get it to work can be to restart the routeD daemon by running "cpstop;cpstart"'
            " or restarting the device. However since this should not happen a case can also be opened with "
            "your technical support provider. In the case of devices in a cluster it is possible that the "
            "issue happens only for one of the nodes and a failover to the other node could lessen the "
            "impact of the issue. Configure one or more NTP servers to be used by this device for clock "
            "synchronization. Log into the Web interface and navigate to System -> Configuration -> Device "
            '-> NTP. Add the desired NTP servers and click "update".',
            "type": "text",
            "position": 1,
        },
        {
            "header": "Description",
            "body": "This system does not have an NTP server configured. Many odd and complicated outages occur due to"
            " lack of clock synchronization between devices. In addition, logs may have the wrong time stamps.",
            "type": "text",
            "position": 0,
        },
    ],
    "resolved": False,
    "revalidated_at": "2020-02-08T18:33:36.788Z",
    "evidence": {"ts": [], "snapshot": []},
    "severity": {"level": 2, "description": "WARN"},
    "notes": [],
    "create_at": "2019-10-07T19:55:42.284Z",
    "updated_at": "2019-10-07T19:55:42.284Z",
}

MISSING_CREDENTIALS_ISSUE = {
    "headline": "Missing Privileged Credentials",
    "device_id": "24bebcb9-6272-48b3-8470-1969191b5023",
    "alert_id": 49539,
    "unique_identifier": "DeviceNotificationAlert",
    "alert_type": "UNAUTOREMEDIATABLE_ISSUE",
    "acknowledged": True,
    "id": "f356c39a-720b-4b1e-a4fe-293b49ff6e6e",
    "alert_blocks": [
        {
            "header": "Description",
            "body": "Missing privileged-command-level credentials, some commands will not be executed.",
            "type": "text",
            "position": 0,
        }
    ],
    "resolved": True,
    "revalidated_at": "2019-10-16T18:11:40.750Z",
    "evidence": {"ts": [], "snapshot": []},
    "severity": {"level": 3, "description": "INFO"},
    "notes": [],
    "create_at": "2019-10-07T19:57:14.058Z",
    "updated_at": "2019-10-16T19:37:35.255Z",
}

PAN_VULNERABILITY_ISSUE_2 = {
    "headline": "Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021",
    "device_id": "01178b51-b8af-4249-aecf-6e5b8da4a04f",
    "alert_id": 49540,
    "unique_identifier": "panos_vulnerability_pansa_20170021_rule",
    "alert_type": "UNAUTOREMEDIATABLE_ISSUE",
    "configuration_set_id": 3409,
    "acknowledged": True,
    "id": "7f0a5ded-571a-4ba0-835d-ba2f76469226",
    "alert_blocks": [
        {
            "header": "Remediation Steps",
            "body": "Palo Alto Networks recommends disabling DNS Proxy for those customers who are affected and are "
            "unable to apply the update.\nFor more information please review: "
            "https://securityadvisories.paloaltonetworks.com/Home/Detail/91",
            "type": "text",
            "position": 1,
        },
        {
            "header": "Description",
            "body": "A Remote Code Execution vulnerability exists in the PAN-OS DNS Proxy. This issue affects "
            "customers who have DNS Proxy enabled in PAN-OS. This issue affects both the Data and Management "
            "planes of the firewall. When DNS Proxy processes a specially crafted fully qualified domain "
            "names (FQDN), it is possible to execute code on the firewall. (Ref # PAN-77516 / CVE-2017-8390)."
            "\nVendor Severity Rating: Critical",
            "type": "text",
            "position": 0,
        },
    ],
    "resolved": False,
    "revalidated_at": "2020-02-08T19:08:14.373Z",
    "evidence": {"ts": [], "snapshot": []},
    "severity": {"level": 1, "description": "ERROR"},
    "notes": [],
    "create_at": "2019-10-07T19:55:41.344Z",
    "updated_at": "2020-02-04T21:25:03.289Z",
}

DEVICE_RESPONSE = {
    "name": "CP-R80.20-GW8-2",
    "is_monitored": True,
    "tags": {
        "device-name": "CP-R80.20-GW8-2",
        "hostname": "CP-R80.20-GW8-2",
        "model": "VMware Virtual Platform",
        "ssh": "true",
        "cluster-id": "d54ac2b34461876261a53d2b00131744",
        "linux-based": "true",
        "https": "true",
        "hotfix-jumbo-take": "87",
        "device-ip": "10.11.94.50",
        "os.version": "R80.20",
        "high-availability": "true",
        "clusterxl": "true",
        "device-id": "d28d0ecc-68c6-4045-9a17-826f6877ed9b",
        "routing-bgp": "true",
        "role-firewall": "true",
        "vendor": "checkpoint",
        "os.name": "gaia",
        "nice-path": "/bin/nice",
    },
    "disable_type": "MANUAL",
    "id": "d28d0ecc-68c6-4045-9a17-826f6877ed9b",
    "labels": [{"id": 14, "name": "system-all"}, {"id": 15, "name": "system-checkpoint"}, {"id": 121, "name": "system-radware"}],
    "ip_address": "10.11.94.50",
    "last_interrogation": None,
    "alert_statistics": {"ERROR": 9, "WARN": 3, "INFO": 1},
    "monitoring_enabled": True,
    "last_seen": "20200212T071943Z",
}


def test_get_all_active_issues(requests_mock):
    from Indeni import get_all_active_issues

    page_1 = []
    page_1.append(PAN_VULNERABILITY_ISSUE)
    page_2 = []
    page_2.append(MISSING_CREDENTIALS_ISSUE)
    requests_mock.get(BASE_URL + "issues?page=1&per_page=500&sort_by=created_at.desc&resolved=false", json=page_1)
    requests_mock.get(BASE_URL + "issues?page=2&per_page=500&sort_by=created_at.desc&resolved=false", json=page_2)
    requests_mock.get(BASE_URL + "issues?page=3&per_page=500&sort_by=created_at.desc&resolved=false", json={})

    test_result = get_all_active_issues(500, "created_at.desc", BASE_URL)
    assert len(test_result) == 2


def test_item_to_incident():
    from Indeni import item_to_incident

    incident = item_to_incident(NETWORK_PORT_DOWN_ISSUE)
    assert incident.get("severity") == 4
    assert incident.get("occurred") == "2019-10-07T19:55:39.177Z"
    assert incident.get("updated") == "2020-01-28T06:52:26.875Z"
    assert incident.get("name") == "Network port(s) down"

    incident = item_to_incident(PAN_VULNERABILITY_ISSUE)
    assert incident.get("severity") == 3
    assert incident.get("occurred") == "2019-10-07T19:55:41.344Z"
    assert incident.get("updated") == "2020-02-04T21:25:03.289Z"
    assert incident.get("name") == "Vulnerability in the PAN-OS DNS Proxy PAN-SA-2017-0021"

    incident = item_to_incident(NO_NTP_SERVERS_ISSUE)
    assert incident.get("severity") == 2
    assert incident.get("occurred") == "2019-10-07T19:55:42.284Z"
    assert incident.get("updated") == "2019-10-07T19:55:42.284Z"
    assert incident.get("name") == "No NTP servers configured"

    incident = item_to_incident(MISSING_CREDENTIALS_ISSUE)
    assert incident.get("severity") == 1
    assert incident.get("occurred") == "2019-10-07T19:57:14.058Z"
    assert incident.get("updated") == "2019-10-16T19:37:35.255Z"
    assert incident.get("name") == "Missing Privileged Credentials"


def test_issue_severiy_to_issue_level():
    from Indeni import issue_severity_to_issue_level

    assert issue_severity_to_issue_level("CRITICAL") == 0
    assert issue_severity_to_issue_level("ERROR") == 1
    assert issue_severity_to_issue_level("WARN") == 2
    assert issue_severity_to_issue_level("INFO") == 3


def test_get_device_request(requests_mock):
    from Indeni import get_device_request

    device_id = "d28d0ecc-68c6-4045-9a17-826f6877ed9b"
    requests_mock.get(BASE_URL + "devices/" + device_id, json=DEVICE_RESPONSE)
    test_result = get_device_request(device_id, BASE_URL)
    assert test_result.get("name") == "CP-R80.20-GW8-2"


def test_get_limited_active_issues(requests_mock):
    from Indeni import get_limited_active_issues

    page_0 = []
    page_0.append(NETWORK_PORT_DOWN_ISSUE)
    page_1 = []
    page_1.append(PAN_VULNERABILITY_ISSUE)
    page_2 = []
    page_2.append(MISSING_CREDENTIALS_ISSUE)
    requests_mock.get(BASE_URL + "issues?page=1&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_0)
    requests_mock.get(BASE_URL + "issues?page=2&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_1)
    requests_mock.get(BASE_URL + "issues?page=3&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_2)
    requests_mock.get(BASE_URL + "issues?page=4&per_page=1&sort_by=alert_id.asc&resolved=false", json={})

    test_result, alert_id_index = get_limited_active_issues(1, 0, 5, True, 1, BASE_URL)
    assert len(test_result) == 1
    assert alert_id_index == 49539
    assert test_result[0].get("unique_identifier") == "panos_vulnerability_pansa_20170021_rule"
    assert test_result[0].get("alert_id") == 49517

    test_result, alert_id_index = get_limited_active_issues(1, 49539, 5, True, 1, BASE_URL)
    assert len(test_result) == 0
    assert alert_id_index == 49539

    page_3 = []
    page_3.append(PAN_VULNERABILITY_ISSUE_2)
    requests_mock.get(BASE_URL + "issues?page=4&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_3)
    requests_mock.get(BASE_URL + "issues?page=5&per_page=1&sort_by=alert_id.asc&resolved=false", json={})
    test_result, alert_id_index = get_limited_active_issues(1, 49539, 5, True, 1, BASE_URL)
    assert len(test_result) == 1
    assert alert_id_index == 49540


def test_get_limited_active_issues_filter(requests_mock):
    from Indeni import get_limited_active_issues

    page_0 = []
    page_0.append(NETWORK_PORT_DOWN_ISSUE)
    page_1 = []
    page_1.append(PAN_VULNERABILITY_ISSUE)
    page_2 = []
    page_2.append(MISSING_CREDENTIALS_ISSUE)
    requests_mock.get(BASE_URL + "issues?page=1&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_0)
    requests_mock.get(BASE_URL + "issues?page=2&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_1)
    requests_mock.get(BASE_URL + "issues?page=3&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_2)
    requests_mock.get(BASE_URL + "issues?page=4&per_page=1&sort_by=alert_id.asc&resolved=false", json={})

    test_result, alert_id_index = get_limited_active_issues(1, 0, 5, False, 1, BASE_URL)
    assert len(test_result) == 2
    assert alert_id_index == 49539
    assert test_result[0].get("unique_identifier") == "cross_vendor_network_port_down"
    assert test_result[0].get("alert_id") == 49498
    assert test_result[1].get("unique_identifier") == "panos_vulnerability_pansa_20170021_rule"
    assert test_result[1].get("alert_id") == 49517

    test_result, alert_id_index = get_limited_active_issues(1, 49539, 5, False, 1, BASE_URL)
    assert len(test_result) == 0
    assert alert_id_index == 49539

    page_3 = []
    page_3.append(PAN_VULNERABILITY_ISSUE_2)
    requests_mock.get(BASE_URL + "issues?page=4&per_page=1&sort_by=alert_id.asc&resolved=false", json=page_3)
    requests_mock.get(BASE_URL + "issues?page=5&per_page=1&sort_by=alert_id.asc&resolved=false", json={})
    test_result, alert_id_index = get_limited_active_issues(1, 49539, 5, False, 0, BASE_URL)
    assert len(test_result) == 0
    assert alert_id_index == 49540


def test_get_limited_active_issues_size_filter(requests_mock):
    from Indeni import get_limited_active_issues

    page_0 = []
    page_0.append(NETWORK_PORT_DOWN_ISSUE)
    page_0.append(PAN_VULNERABILITY_ISSUE)
    page_0.append(MISSING_CREDENTIALS_ISSUE)
    requests_mock.get(BASE_URL + "issues?page=1&per_page=3&sort_by=alert_id.asc&resolved=false", json=page_0)
    requests_mock.get(BASE_URL + "issues?page=2&per_page=3&sort_by=alert_id.asc&resolved=false", json={})

    test_result, alert_id_index = get_limited_active_issues(3, 0, 2, False, 3, BASE_URL)
    assert len(test_result) == 2
    assert alert_id_index == 49517
    assert test_result[0].get("unique_identifier") == "cross_vendor_network_port_down"
    assert test_result[0].get("alert_id") == 49498
    assert test_result[1].get("unique_identifier") == "panos_vulnerability_pansa_20170021_rule"
    assert test_result[1].get("alert_id") == 49517

    test_result, alert_id_index = get_limited_active_issues(3, 49517, 2, False, 3, BASE_URL)
    assert len(test_result) == 1
    assert test_result[0].get("unique_identifier") == "DeviceNotificationAlert"
    assert test_result[0].get("alert_id") == 49539
    assert alert_id_index == 49539

    page_3 = []
    page_3.append(PAN_VULNERABILITY_ISSUE_2)
    requests_mock.get(BASE_URL + "issues?page=2&per_page=3&sort_by=alert_id.asc&resolved=false", json=page_3)
    requests_mock.get(BASE_URL + "issues?page=3&per_page=3&sort_by=alert_id.asc&resolved=false", json={})
    test_result, alert_id_index = get_limited_active_issues(3, 49539, 2, False, 3, BASE_URL)
    assert len(test_result) == 1
    assert test_result[0].get("alert_id") == 49540
    assert alert_id_index == 49540
